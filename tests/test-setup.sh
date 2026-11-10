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
	cp files/keensteer.conf "$root/opt/etc/keensteer.conf.example"

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
	'show running-config')
		[ ! -r "$KEENSTEER_ROOT/tmp/running-config" ] || cat "$KEENSTEER_ROOT/tmp/running-config"
		;;
	'show interface WifiMaster1/AccessPoint5')
		[ ! -r "$KEENSTEER_ROOT/tmp/ap5" ] || cat "$KEENSTEER_ROOT/tmp/ap5"
		;;
	interface\ *|mws\ *)
		if [ -e "$KEENSTEER_ROOT/tmp/mws-member" ]; then
			echo 'Core::Configurator: interface: execute blocked in MWS member mode'
			exit 126
		fi
		echo "$2" >> "$KEENSTEER_ROOT/tmp/ndmc.log"
		;;
	*) ;;
esac
EOF
	chmod 0755 "$root/bin/ndmc"

	cat > "$root/bin/ssh" <<EOF
#!/bin/sh
host=\${1#root@}
case "\$*" in
	*probe*)
		if [ -r "$root/tmp/probe-\$host" ]; then
			cat >/dev/null
			cat "$root/tmp/probe-\$host"
			exit 0
		fi
		;;
esac
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

fresh_install()
{
	make_root
	mkdir -p "$root/opt/etc/init.d"
	rm -f "$root/opt/etc/keensteer.conf.example"
	DESTDIR=$root ./install.sh >/dev/null
	[ ! -e "$config" ]
	cmp -s files/keensteer.conf "$root/opt/etc/keensteer.conf.example"

	cp files/keensteer.conf "$config"
	printf 'guest\n' > "$guest"
	DESTDIR=$root ./install.sh >/dev/null
	[ ! -e "$config" ] && [ -e "$guest" ]

	printf 'custom\n' > "$config"
	DESTDIR=$root ./install.sh >/dev/null
	grep -qx custom "$config"
	grep -qx guest "$guest"
}

delete_segments()
{
	make_root
	mkdir -p "$root/opt/etc/init.d"
	printf '#!/bin/sh\necho "$1" >> "%s"\n' "$root/tmp/init.log" > "$root/opt/etc/init.d/S99keensteer"
	chmod 0755 "$root/opt/etc/init.d/S99keensteer"
	printf 'home\n' > "$config"
	printf 'guest\n' > "$guest"

	run_setup -d -s Bridge1 >/dev/null
	[ -e "$config" ] && [ ! -e "$guest" ]
	[ ! -e "$guest.bak" ]
	grep -qx restart "$root/tmp/init.log"

	: > "$root/tmp/init.log"
	run_setup -d >/dev/null
	[ ! -e "$config" ]
	[ ! -e "$config.bak" ]
	grep -qx restart "$root/tmp/init.log"
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
	sed '1,8d' "$openwrt" | cmp -s files/keensteer-openwrt.sh -
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
	mkdir -p "$root/sys/class/net/ra8.5" "$root/sys/class/net/br0/brif/ra8.5"
	printf '%s\n' 02:11:22:33:45:50 > "$root/sys/class/net/ra8.5/address"
	printf '%s\n' 02:11:22:33:44:60 > "$root/sys/class/net/ra1/address"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'bss=ra0,keenetic-hero.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:02:11:22:33:44:51-00' "$config"
	grep -qx 'bss=ra8,keenetic-hero.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:02:11:22:33:44:51-10' "$config"
	if grep -q 'ra1' "$config"; then exit 1; fi
	if grep -q 'ra8.5' "$config"; then exit 1; fi
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

guest_only()
{
	make_root
	for ifname in br1 ra1 rai1; do mkdir -p "$root/sys/class/net/$ifname"; done
	printf '%s\n' 02:11:22:33:44:70 > "$root/sys/class/net/br1/address"
	printf '%s\n' 02:11:22:33:44:60 > "$root/sys/class/net/ra1/address"
	printf '%s\n' 02:11:22:33:45:60 > "$root/sys/class/net/rai1/address"
	mkdir -p "$root/sys/class/net/br1/brif/ra1" "$root/sys/class/net/br1/brif/rai1"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup -s br1 >/dev/null
	[ ! -e "$config" ]
	grep -qx 'interface=br1' "$guest"
}

init_without_config()
{
	make_root
	KEENSTEER_ROOT=$root sh ./files/S99keensteer start > "$root/tmp/init.out"
	grep -q 'not configured' "$root/tmp/init.out"
	KEENSTEER_ROOT=$root sh ./files/S99keensteer check > "$root/tmp/init.out"
	grep -q 'not configured' "$root/tmp/init.out"
	KEENSTEER_ROOT=$root sh ./files/S99keensteer restart > "$root/tmp/init.out"
	grep -q 'not configured' "$root/tmp/init.out"
}

mobility_domain_default()
{
	make_root
	printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20|4142\n' > "$root/tmp/probe-192.168.1.2"
	printf '192.168.1.2\nn\n\ny\n' | run_setup >/dev/null
	grep -qx "mobility_domain='4142'" "$openwrt"
	grep -qx 'interface WifiMaster0/AccessPoint0 ft mdid AB' "$root/tmp/ndmc.log"

	printf '192.168.1.2\nn\nKN\ny\n' | run_setup > "$root/tmp/out" 2>&1
	grep -q 'replacing OpenWrt mobility domain 4142' "$root/tmp/out"
	grep -qx "mobility_domain='4b4e'" "$openwrt"

	rm "$root/tmp/probe-192.168.1.2"
	printf 'interface WifiMaster0/AccessPoint0\n    ft mdid CD\n' > "$root/tmp/running-config"
	printf '192.168.1.2\nn\n\ny\n' | run_setup > "$root/tmp/out" 2>&1
	grep -qx "mobility_domain='4344'" "$openwrt"
	if grep -q 'replacing OpenWrt mobility domain' "$root/tmp/out"; then exit 1; fi
}

saved_hosts_default()
{
	make_root
	printf '192.168.1.2\ny\n192.168.1.3\nn\nKN\ny\n' | run_setup >/dev/null
	rm -f "$openwrt" "$openwrt2"
	printf '\n\n\n\n\ny\n' | run_setup >/dev/null
	[ -e "$openwrt" ] && [ -e "$openwrt2" ]
	grep -q ',192.168.1.3,' "$config"

	rm -f "$openwrt" "$openwrt2"
	printf '\nn\n\ny\n' | run_setup >/dev/null
	[ -e "$openwrt" ] && [ ! -e "$openwrt2" ]
	if grep -q ',192.168.1.3,' "$config"; then exit 1; fi
}

peer_key_kept()
{
	make_root
	old=0123456789abcdef0123456789abcdef
	{
		printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20|\n'
		printf 'default_radio1|phy1-ap0|example-wifi|02:aa:bb:cc:dd:30|\n'
		printf '@key|02:aa:bb:cc:dd:30|%s\n' "$old"
	} > "$root/tmp/probe-192.168.1.2"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx "peer_key='$old'" "$openwrt"
	if grep -qx "rrb_key='$old'" "$openwrt"; then exit 1; fi

	printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20|\n@key|02:aa:bb:cc:dd:99|%s\n' "$old" \
		> "$root/tmp/probe-192.168.1.2"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	if grep -qx "peer_key='$old'" "$openwrt"; then exit 1; fi
}

wifi_system_member()
{
	make_root
	touch "$root/tmp/mws-member"
	printf 'interface WifiMaster0/AccessPoint0\n    ft mdid KN\n' > "$root/tmp/running-config"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup > "$root/tmp/out"
	grep -q 'Wi-Fi System member' "$root/tmp/out"
	[ -e "$config" ] && [ -e "$openwrt" ] && [ ! -e "$root/tmp/ndmc.log" ]

	rm -f "$config" "$openwrt"
	if printf '192.168.1.2\nn\nXY\ny\n' | run_setup >/dev/null 2>&1; then
		echo "member accepted another Mobility Domain" >&2
		exit 1
	fi
	[ ! -e "$config" ] && [ ! -e "$openwrt" ]

	rm "$root/tmp/running-config"
	printf '192.168.1.2\nn\nXY\ny\n' | run_setup > "$root/tmp/out"
	grep -q 'must use mobility domain XY' "$root/tmp/out"
	grep -qx "mobility_domain='5859'" "$openwrt"
}

wlan_profile()
{
	make_root
	{
		printf 'interface WifiMaster0/AccessPoint0\n    ssid example-wifi\n    ft mdid q%%\n!\n'
		printf 'mws wlan DEFAULT__\n    factory default\n    band all\n    bind Bridge0\n    enable\n!\n'
		printf 'mws wlan GUEST\n    bind Bridge1\n    enable\n!\n'
	} > "$root/tmp/running-config"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'mws wlan DEFAULT__ ft enable' "$root/tmp/ndmc.log"
	grep -qx 'mws wlan DEFAULT__ ft mdid KN' "$root/tmp/ndmc.log"
	grep -qx 'mws wlan DEFAULT__ rrm enable' "$root/tmp/ndmc.log"
	if grep -qE '^interface |GUEST' "$root/tmp/ndmc.log"; then exit 1; fi

	rm "$root/tmp/ndmc.log"
	printf '192.168.1.2\nn\n\ny\n' | run_setup >/dev/null
	grep -qx "mobility_domain='7125'" "$openwrt"
	grep -qx 'mws wlan DEFAULT__ ft mdid "q%"' "$root/tmp/ndmc.log"

	printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20|2541\n' > "$root/tmp/probe-192.168.1.2"
	printf '192.168.1.2\nn\n\ny\n' | run_setup >/dev/null
	grep -qx "mobility_domain='2541'" "$openwrt"
}

runtime_detection()
{
	make_root
	printf 'Default\nBssidNum=2\nFtR0khId1=Keenetic:aa:bb:cc:dd:ee:ff-00\n' > "$root/tmp/RT2860AP.dat"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'bss=ra0,keenetic-hero.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:aa:bb:cc:dd:ee:ff-00' "$config"
	grep -qx 'bss=ra8,keenetic-hero.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:aa:bb:cc:dd:ee:ff-10' "$config"

	make_root
	printf 'br0\n5\nra0\nra8\nrai5\nra9\n' > "$root/var/run/bndstrg-br0.conf"
	mkdir -p "$root/sys/class/net/rai5" "$root/sys/class/net/ra9"
	printf '%s\n' 02:11:22:33:45:55 > "$root/sys/class/net/rai5/address"
	printf '%s\n' 02:11:22:33:45:59 > "$root/sys/class/net/ra9/address"
	printf '      mac: 02:11:22:33:45:55\n     ssid: example-wifi\n' > "$root/tmp/ap5"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'bss=rai5,keenetic-hero.5g,example-wifi,02:11:22:33:45:55,44,128,,Keenetic:02:11:22:33:44:51-15' "$config"
	if grep -q 'ra9' "$config"; then exit 1; fi

	printf '      mac: 02:11:22:33:45:55\n     ssid: bad,ssid\n' > "$root/tmp/ap5"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null 2>"$root/tmp/err"
	grep -q 'skipping rai5' "$root/tmp/err"
	if grep -q 'rai5' "$config"; then exit 1; fi

	make_root
	printf 'unexpected\nformat\n' > "$root/var/run/bndstrg-br0.conf"
	mkdir -p "$root/sys/class/net/br0/brif/ra0" "$root/sys/class/net/br0/brif/ra8"
	printf '192.168.1.2\nn\nKN\ny\n' | run_setup >/dev/null
	grep -qx 'interface=br0' "$config"
	grep -q '^bss=ra8,' "$config"
}

make_openwrt()
{
	sim=$root/openwrt
	mkdir -p "$sim/bin" "$sim/init.d"
	: > "$sim/log"
	printf 'wireless.radio0\twifi-iface\nwireless.radio0.network\tlan\n' > "$sim/work"
	printf 'wireless.radio0.r0kh\taa:aa:aa:aa:aa:aa,manual,deadbeef\n' >> "$sim/work"
	cp "$sim/work" "$sim/committed"
	cat > "$sim/bin/uci" <<'EOF'
#!/bin/sh
[ "$1" = -q ] && shift
c=$1
shift
w=$SIM/work
case "$c" in
	get)
		v=$(awk -F'\t' -v k="$1" '$1 == k { printf "%s%s", (n++ ? " " : ""), $2 }' "$w")
		[ -n "$v" ] || exit 1
		printf '%s\n' "$v"
		;;
	set)
		awk -F'\t' -v k="${1%%=*}" '$1 != k' "$w" > "$w.t"
		mv "$w.t" "$w"
		printf '%s\t%s\n' "${1%%=*}" "${1#*=}" >> "$w"
		;;
	add_list) printf '%s\t%s\n' "${1%%=*}" "${1#*=}" >> "$w" ;;
	del_list)
		awk -F'\t' -v k="${1%%=*}" -v v="${1#*=}" '!($1 == k && $2 == v)' "$w" > "$w.t"
		mv "$w.t" "$w"
		;;
	show) sed 's/\t/=/' "$w" ;;
	changes) cmp -s "$w" "$SIM/committed" || echo changed ;;
	commit) cp "$w" "$SIM/committed" ;;
	revert) cp "$SIM/committed" "$w" ;;
	*) exit 2 ;;
esac
EOF
	printf '#!/bin/sh\necho "wifi $*" >> "$SIM/log"\n' > "$sim/bin/wifi"
	printf '#!/bin/sh\necho 0\n' > "$sim/bin/id"
	printf '#!/bin/sh\nexit 0\n' > "$sim/bin/socat"
	printf '#!/bin/sh\nexit 0\n' > "$sim/rc.common"
	chmod 0755 "$sim/bin/uci" "$sim/bin/wifi" "$sim/bin/id" "$sim/bin/socat" "$sim/rc.common"
}

apply_openwrt()
{
	{
		printf "listen_ip='192.168.1.2'\nmobility_domain='4b4e'\nrrb_key='%s'\npeer_key='peer'\nkeenetic_mac='%s'\n" "$2" "$1"
		printf "keenetic_bss='%s|Keenetic:%s-00 '\n" "$1" "$1"
		printf "interfaces='radio0|02aabbccdd20|02:aa:bb:cc:dd:20 '\n"
		printf "peers='02:aa:bb:cc:dd:20|02aabbccdd20 02:aa:bb:cc:dd:30|02aabbccdd30 '\n"
		sed "s#/etc/init.d#$sim/init.d#g; s#/etc/rc.common#$sim/rc.common#g" files/keensteer-openwrt.sh
	} | SIM=$sim PATH=$sim/bin:$PATH sh >/dev/null
}

openwrt_apply()
{
	make_root
	make_openwrt
	a=02:11:22:33:44:50
	b=02:66:77:88:99:50

	apply_openwrt "$a" keya
	[ "$(grep -c '^wifi reload' "$sim/log")" = 1 ]
	cp "$sim/committed" "$sim/first"

	apply_openwrt "$a" keya
	[ "$(grep -c '^wifi reload' "$sim/log")" = 1 ]
	sort "$sim/first" > "$sim/first.sorted"
	sort "$sim/committed" | cmp -s - "$sim/first.sorted"

	apply_openwrt "$b" keyb
	[ "$(grep -c '^wifi reload' "$sim/log")" = 2 ]
	grep -qF "$a,Keenetic:$a-00,keya" "$sim/committed"
	grep -qF "$b,Keenetic:$b-00,keyb" "$sim/committed"
	grep -qF '02:aa:bb:cc:dd:30,02aabbccdd30,peer' "$sim/committed"
	grep -qF 'aa:aa:aa:aa:aa:aa,manual,deadbeef' "$sim/committed"
	if grep -F 'keyb' "$sim/committed" | grep -qF '02:aa:bb:cc:dd:30'; then exit 1; fi
	[ -z "$(sort "$sim/committed" | uniq -d)" ]

	apply_openwrt "$a" rotated
	grep -qF "$a,Keenetic:$a-00,rotated" "$sim/committed"
	if grep -qF "$a,Keenetic:$a-00,keya" "$sim/committed"; then exit 1; fi
	grep -qF "$b,Keenetic:$b-00,keyb" "$sim/committed"
}

uninstall_keeps_config()
{
	make_root
	mkdir -p "$root/opt/etc/init.d"
	DESTDIR=$root ./install.sh >/dev/null
	printf 'custom\n' > "$config"
	printf 'guest\n' > "$guest"
	printf 'key\n' > "$key"
	DESTDIR=$root ./uninstall.sh >/dev/null
	[ ! -e "$root/opt/etc/keensteer.conf.example" ]
	grep -qx custom "$config"
	grep -qx guest "$guest"
	grep -qx key "$key"
}

fresh_install
delete_segments
init_without_config
uninstall_keeps_config
reject_unmatched_host
cleanup_on_sigterm
guided_home_setup
single_band_fallback
guest_segment
guest_only
mobility_domain_default
saved_hosts_default
peer_key_kept
wifi_system_member
wlan_profile
runtime_detection
openwrt_apply

echo "ok setup"
