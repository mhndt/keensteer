#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$root/bin" "$root/opt/etc" "$root/tmp" "$root/var/run"
for ifname in br0 ra0 ra8; do
	mkdir -p "$root/sys/class/net/$ifname"
done

printf '%s\n' 02:11:22:33:44:50 > "$root/sys/class/net/br0/address"
printf '%s\n' 02:11:22:33:44:50 > "$root/sys/class/net/ra0/address"
printf '%s\n' 02:11:22:33:45:50 > "$root/sys/class/net/ra8/address"
printf 'br0\n5\nra0\nra8\n' > "$root/var/run/bndstrg-br0.conf"

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
		;;
	*)
		cat > "$root/tmp/applied-\$host.sh"
		printf 'Configured OpenWrt for keensteer.\n'
		;;
esac
EOF
chmod 0755 "$root/bin/ssh"

if printf '192.168.1.2\ny\n192.168.1.9\n' | \
	KEENSTEER_ROOT=$root KEENSTEER_NDMC=$root/bin/ndmc \
	KEENSTEER_SSH=$root/bin/ssh \
	./files/keensteer-setup >/dev/null 2>&1; then
	echo "host without matching access point was accepted" >&2
	exit 1
fi
[ ! -e "$root/opt/etc/keensteer.conf" ]

cat > "$root/bin/slowssh" <<'EOF2'
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
EOF2
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

printf '192.168.1.2\ny\n192.168.1.3\nn\nKN\ny\n' | \
	KEENSTEER_ROOT=$root KEENSTEER_NDMC=$root/bin/ndmc \
	KEENSTEER_SSH=$root/bin/ssh \
	./files/keensteer-setup >/dev/null

config=$root/opt/etc/keensteer.conf
openwrt=$root/tmp/applied-192.168.1.2.sh
openwrt2=$root/tmp/applied-192.168.1.3.sh
key=$root/opt/etc/keensteer.rrb.key

grep -qx 'bss=ra0,keenetic-hero.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:02:11:22:33:44:51-00' "$config"
grep -qx 'bss=ra8,keenetic-hero.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:02:11:22:33:44:51-10' "$config"
grep -qx 'ft_peer=02:aa:bb:cc:dd:20,02:aa:bb:cc:dd:20,192.168.1.2,02:aa:bb:cc:dd:20,02aabbccdd20' "$config"
grep -qx 'ft_peer=02:aa:bb:cc:dd:30,02:aa:bb:cc:dd:30,192.168.1.2,02:aa:bb:cc:dd:30,02aabbccdd30' "$config"
grep -qx 'ft_peer=02:aa:bb:cc:dd:40,02:aa:bb:cc:dd:40,192.168.1.3,02:aa:bb:cc:dd:40,02aabbccdd40' "$config"
grep -q "listen_ip='192.168.1.2'" "$openwrt"
grep -q "mobility_domain='4b4e'" "$openwrt"
grep -q "replace_entry 'default_radio0' r0kh '02:11:22:33:44:50,Keenetic:02:11:22:33:44:51-10,'" "$openwrt"
grep -q "replace_entry 'default_radio1' r1kh '02:11:22:33:44:50,02:11:22:33:45:50,'" "$openwrt"
grep -q "remove_owner 'default_radio0' '02:11:22:33:44:50'" "$openwrt"
grep -q "remove_owner 'default_radio0' '02:11:22:33:44:50'" "$openwrt2"
grep -q '^remove_owner()' "$openwrt"
if ls "$root/tmp"/keensteer-openwrt-* >/dev/null 2>&1; then exit 1; fi
grep -q 'wireless.default_radio0.ieee80211r=1' "$openwrt"
grep -q 'wireless.default_radio1.ieee80211r=1' "$openwrt"
grep -q 'wireless.default_radio0.ieee80211k=1' "$openwrt"
grep -q 'wireless.default_radio0.bss_transition=1' "$openwrt"
grep -q "02:aa:bb:cc:dd:30,02aabbccdd30" "$openwrt"
grep -q "replace_entry 'default_radio0' r0kh '02:aa:bb:cc:dd:40,02aabbccdd40,'" "$openwrt"
grep -q 'TCP-LISTEN:3517' "$openwrt"
grep -q 'procd_set_param respawn 3600 5 0' "$openwrt"
grep -q '/etc/init.d/keensteer-rrb-sink status' "$openwrt"
grep -q "listen_ip='192.168.1.3'" "$openwrt2"
grep -q 'wireless.default_radio0.ieee80211r=1' "$openwrt2"
if grep -q 'wireless.default_radio1' "$openwrt2"; then exit 1; fi
grep -q "replace_entry 'default_radio0' r0kh '02:11:22:33:44:50,Keenetic:02:11:22:33:44:51-00,'" "$openwrt2"
grep -q "replace_entry 'default_radio0' r1kh '02:aa:bb:cc:dd:20,02:aa:bb:cc:dd:20,'" "$openwrt2"
grep -q "replace_entry 'default_radio0' r0kh '02:aa:bb:cc:dd:30,02aabbccdd30,'" "$openwrt2"
[ ! -e "$root/tmp/keensteer-openwrt-192.168.1.2.sh" ]
[ ! -e "$root/tmp/keensteer-openwrt-192.168.1.3.sh" ]
grep -Eq '^[0-9a-f]{64}$' "$key"
[ "$(stat -c '%a' "$key")" = 600 ]
dash -n "$openwrt" "$openwrt2"

echo "ok setup"
