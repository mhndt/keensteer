#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

config=$root/opt/etc/keensteer.conf
guest=$root/opt/etc/keensteer-br1.conf
key=$root/opt/etc/keensteer.rrb.key
openwrt=$root/tmp/applied-192.168.1.2.sh
openwrt2=$root/tmp/applied-192.168.1.3.sh

make_root()
{
	rm -rf "${root:?}"/*
	mkdir -p "$root/bin" "$root/opt/etc" "$root/tmp" "$root/var/run"
	for ifname in br0 ra0 ra8; do
		mkdir -p "$root/sys/class/net/$ifname"
	done

	printf '%s\n' 02:11:22:33:44:50 > "$root/sys/class/net/br0/address"
	printf '%s\n' 02:11:22:33:44:50 > "$root/sys/class/net/ra0/address"
	printf '%s\n' 02:11:22:33:45:50 > "$root/sys/class/net/ra8/address"
	printf 'br0\n5\nra0\nra8\n' > "$root/var/run/bndstrg-br0.conf"
	cp files/keensteer-openwrt.sh "$root/opt/etc/keensteer-openwrt.sh"

	cat > "$root/bin/ndmc" <<'EOF'
#!/bin/sh
case "$2" in
	'show system')
		printf '     hostname: Keenetic-Hero\n'
		;;
	'show interface WifiMaster0')
		printf '       channel: 10\n     bandwidth: 20\n'
		;;
	'show interface WifiMaster1')
		printf '       channel: 44\n     bandwidth: 80\n'
		;;
	'show interface WifiMaster0/AccessPoint0')
		printf '              mac: 02:11:22:33:44:50\n             ssid: example-wifi\n'
		;;
	'show interface WifiMaster1/AccessPoint0')
		printf '              mac: 02:11:22:33:45:50\n             ssid: example-wifi\n'
		;;
	'show interface WifiMaster0/AccessPoint1')
		printf '              mac: 02:11:22:33:44:60\n             ssid: example-guest\n'
		;;
	'show interface WifiMaster1/AccessPoint1')
		printf '              mac: 02:11:22:33:45:60\n             ssid: example-guest\n'
		;;
	*) ;;
esac
EOF
	chmod 0755 "$root/bin/ndmc"

	cat > "$root/bin/ssh" <<EOF
#!/bin/sh
host=\${1#root@}
case "\$*" in
	*192.168.1.3*probe*)
		cat >/dev/null
		printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:40\n'
		;;
	*192.168.1.9*probe*)
		cat >/dev/null
		printf 'default_radio0|phy0-ap0|other-wifi|02:aa:bb:cc:dd:90\n'
		;;
	*probe*)
		cat >/dev/null
		printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20\n'
		printf 'default_radio1|phy1-ap0|example-wifi|02:aa:bb:cc:dd:30\n'
		printf 'guest_radio0|phy0-ap1|example-guest|02:aa:bb:cc:dd:50\n'
		;;
	*)
		cat > "$root/tmp/applied-\$host.sh"
		printf 'Configured OpenWrt for keensteer.\n'
		;;
esac
EOF
	chmod 0755 "$root/bin/ssh"
}

run_setup()
{
	KEENSTEER_ROOT=$root KEENSTEER_NDMC=$root/bin/ndmc KEENSTEER_SSH=$root/bin/ssh \
		./files/keensteer-setup "$@"
}

reject_unmatched_host()
{
	make_root
	if printf '192.168.1.2\ny\n192.168.1.9\n' | run_setup >/dev/null 2>&1; then
		echo "host without matching access point was accepted" >&2
		exit 1
	fi
	[ ! -e "$config" ]
}

cleanup_on_sigterm()
{
	make_root
	cat > "$root/bin/slowssh" <<'EOF'
#!/bin/sh
case "$*" in
	*probe*)
		cat >/dev/null
		printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20\n'
		;;
	*)
		cat >/dev/null
		sleep 30
		;;
esac
EOF
	chmod 0755 "$root/bin/slowssh"
	printf '192.168.1.2\nn\nKN\ny\n' | \
		KEENSTEER_ROOT=$root KEENSTEER_NDMC=$root/bin/ndmc \
		KEENSTEER_SSH=$root/bin/slowssh \
		setsid ./files/keensteer-setup >/dev/null 2>&1 &
	pid=$!
	sleep 1
	[ -e "$root/tmp/keensteer-openwrt-192.168.1.2.sh" ]
	kill -TERM "-$pid"
	if wait "$pid"; then
		echo "helper survived SIGTERM" >&2
		exit 1
	fi
	if ls "$root/tmp"/keensteer-openwrt-* >/dev/null 2>&1; then
		echo "temporary files left after SIGTERM" >&2
		exit 1
	fi
}

guided_home_setup()
{
	make_root
	mkdir -p "$root/opt/etc/init.d"
	printf '#!/bin/sh\necho "$1" >> "%s"\n' "$root/tmp/init.log" > "$root/opt/etc/init.d/S99keensteer"
	chmod 0755 "$root/opt/etc/init.d/S99keensteer"

	printf '192.168.1.2\ny\n192.168.1.3\nn\nKN\ny\n' | run_setup >/dev/null

	grep -qx 'bss=ra0,keenetic-hero.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:02:11:22:33:44:51-00' "$config"
	grep -qx 'bss=ra8,keenetic-hero.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:02:11:22:33:44:51-10' "$config"
	grep -qx 'ft_peer=02:aa:bb:cc:dd:20,02:aa:bb:cc:dd:20,192.168.1.2,02:aa:bb:cc:dd:20,02aabbccdd20' "$config"
	grep -qx 'ft_peer=02:aa:bb:cc:dd:30,02:aa:bb:cc:dd:30,192.168.1.2,02:aa:bb:cc:dd:30,02aabbccdd30' "$config"
	grep -qx 'ft_peer=02:aa:bb:cc:dd:40,02:aa:bb:cc:dd:40,192.168.1.3,02:aa:bb:cc:dd:40,02aabbccdd40' "$config"
	grep -qx "listen_ip='192.168.1.2'" "$openwrt"
	grep -qx "mobility_domain='4b4e'" "$openwrt"
	grep -qx "keenetic_mac='02:11:22:33:44:50'" "$openwrt"
	grep -qx "keenetic_bss='02:11:22:33:44:50|Keenetic:02:11:22:33:44:51-00 02:11:22:33:45:50|Keenetic:02:11:22:33:44:51-10 '" "$openwrt"
	grep -qx "interfaces='default_radio0|02aabbccdd20|02:aa:bb:cc:dd:20 default_radio1|02aabbccdd30|02:aa:bb:cc:dd:30 '" "$openwrt"
	grep -qx "peers='02:aa:bb:cc:dd:20|02aabbccdd20 02:aa:bb:cc:dd:30|02aabbccdd30 02:aa:bb:cc:dd:40|02aabbccdd40 '" "$openwrt"
	grep -q '^remove_owner()' "$openwrt"
	grep -q '^replace_entry()' "$openwrt"
	if ls "$root/tmp"/keensteer-openwrt-* >/dev/null 2>&1; then exit 1; fi
	grep -q 'ieee80211r=1' "$openwrt"
	grep -q 'ieee80211k=1' "$openwrt"
	grep -q 'bss_transition=1' "$openwrt"
	grep -q 'TCP-LISTEN:3517' "$openwrt"
	grep -q 'procd_set_param respawn 3600 5 0' "$openwrt"
	grep -q '/etc/init.d/keensteer-rrb-sink status' "$openwrt"
	grep -qx "listen_ip='192.168.1.3'" "$openwrt2"
	grep -qx "keenetic_mac='02:11:22:33:44:50'" "$openwrt2"
	grep -qx "interfaces='default_radio0|02aabbccdd40|02:aa:bb:cc:dd:40 '" "$openwrt2"
	grep -qx "peers='02:aa:bb:cc:dd:20|02aabbccdd20 02:aa:bb:cc:dd:30|02aabbccdd30 02:aa:bb:cc:dd:40|02aabbccdd40 '" "$openwrt2"
	if grep -q 'default_radio1' "$openwrt2"; then exit 1; fi
	sed '1,7d' "$openwrt" | cmp -s files/keensteer-openwrt.sh -
	[ ! -e "$root/tmp/keensteer-openwrt-192.168.1.2.sh" ]
	[ ! -e "$root/tmp/keensteer-openwrt-192.168.1.3.sh" ]
	grep -Eq '^[0-9a-f]{64}$' "$key"
	grep -qx restart "$root/tmp/init.log"
	[ "$(stat -c '%a' "$key")" = 600 ]
	dash -n "$openwrt" "$openwrt2"
}

single_band_fallback()
{
	# single-band models run no band steering daemon: the access points are the ports of the Home bridge
	make_root
	rm -f "$root/var/run/bndstrg-br0.conf"
	mkdir -p "$root/sys/class/net/br0/brif/ra0" "$root/sys/class/net/br0/brif/ra8" "$root/sys/class/net/ra1"
	printf '%s\n' 02:11:22:33:44:60 > "$root/sys/class/net/ra1/address"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'bss=ra0,keenetic-hero.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:02:11:22:33:44:51-00' "$config"
	grep -qx 'bss=ra8,keenetic-hero.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:02:11:22:33:44:51-10' "$config"
	if grep -q 'ra1' "$config"; then exit 1; fi
	grep -qx 'interface=br0' "$config"
}

guest_segment()
{
	# another segment: its access points are the bridge ports of the chosen bridge
	make_root
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	cp "$config" "$root/tmp/home.conf"
	for ifname in br1 ra1 rai1; do mkdir -p "$root/sys/class/net/$ifname"; done
	printf '%s\n' 02:11:22:33:44:70 > "$root/sys/class/net/br1/address"
	printf '%s\n' 02:11:22:33:44:60 > "$root/sys/class/net/ra1/address"
	printf '%s\n' 02:11:22:33:45:60 > "$root/sys/class/net/rai1/address"
	mkdir -p "$root/sys/class/net/br1/brif/ra1" "$root/sys/class/net/br1/brif/rai1"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup -s Bridge1 >/dev/null
	grep -qx 'interface=br1' "$guest"
	grep -qx 'bss=ra1,keenetic-hero.br1.2g,example-guest,02:11:22:33:44:60,10,81,,Keenetic:02:11:22:33:44:51-01' "$guest"
	grep -qx 'bss=rai1,keenetic-hero.br1.5g,example-guest,02:11:22:33:45:60,44,128,,Keenetic:02:11:22:33:44:51-11' "$guest"
	grep -qx 'ft_peer=02:aa:bb:cc:dd:50,02:aa:bb:cc:dd:50,192.168.1.2,02:aa:bb:cc:dd:50,02aabbccdd50' "$guest"
	if grep -q 'example-wifi' "$guest"; then exit 1; fi
	grep -qx "keenetic_mac='02:11:22:33:44:70'" "$openwrt"
	grep -qx "keenetic_bss='02:11:22:33:44:60|Keenetic:02:11:22:33:44:51-01 02:11:22:33:45:60|Keenetic:02:11:22:33:44:51-11 '" "$openwrt"
	grep -qx "interfaces='guest_radio0|02aabbccdd50|02:aa:bb:cc:dd:50 '" "$openwrt"
	grep -qF 'usteer.@usteer[-1].network' "$openwrt"
	if grep -q 'default_radio0' "$openwrt"; then exit 1; fi
	cmp -s "$config" "$root/tmp/home.conf"
	[ "$(stat -c '%a' "$guest")" = 600 ]
	dash -n "$openwrt"
}

reject_unmatched_host
cleanup_on_sigterm
guided_home_setup
single_band_fallback
guest_segment

echo "ok setup"
