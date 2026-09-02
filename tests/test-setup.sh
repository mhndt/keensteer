#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM

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

cat > "$root/bin/ssh" <<'EOF'
#!/bin/sh
case "$*" in
	*probe*)
		cat >/dev/null
		printf 'default_radio0|phy0-ap0|example-wifi|02:aa:bb:cc:dd:20\n'
		printf 'default_radio1|phy1-ap0|example-wifi|02:aa:bb:cc:dd:30\n'
		;;
	*)
		cat >/dev/null
		printf 'Configured OpenWrt for keensteer.\n'
		;;
esac
EOF
chmod 0755 "$root/bin/ssh"

printf '192.0.2.20\nKN\ny\n' | \
	KEENSTEER_ROOT=$root KEENSTEER_NDMC=$root/bin/ndmc \
	KEENSTEER_SSH=$root/bin/ssh \
	./files/keensteer-setup >/dev/null

config=$root/opt/etc/keensteer.conf
openwrt=$root/tmp/keensteer-openwrt.sh
key=$root/opt/etc/keensteer.rrb.key

grep -qx 'bss=ra0,keenetic.2g,example-wifi,02:11:22:33:44:50,10,81,,Keenetic:02:11:22:33:44:51-00' "$config"
grep -qx 'bss=ra8,keenetic.5g,example-wifi,02:11:22:33:45:50,44,128,,Keenetic:02:11:22:33:44:51-10' "$config"
grep -qx 'ft_peer=02:aa:bb:cc:dd:20,02:aa:bb:cc:dd:20,192.0.2.20,02:aa:bb:cc:dd:20,02aabbccdd20' "$config"
grep -qx 'ft_peer=02:aa:bb:cc:dd:30,02:aa:bb:cc:dd:30,192.0.2.20,02:aa:bb:cc:dd:30,02aabbccdd30' "$config"
grep -q "mobility_domain='4b4e'" "$openwrt"
grep -q "replace_entry 'default_radio0' r0kh '02:11:22:33:44:50,Keenetic:02:11:22:33:44:51-10,'" "$openwrt"
grep -q "replace_entry 'default_radio1' r1kh '02:11:22:33:44:50,02:11:22:33:45:50,'" "$openwrt"
grep -q 'wireless.default_radio0.ieee80211r=1' "$openwrt"
grep -q 'wireless.default_radio1.ieee80211r=1' "$openwrt"
grep -q "02:aa:bb:cc:dd:30,02aabbccdd30" "$openwrt"
grep -q 'TCP-LISTEN:3517' "$openwrt"
grep -Eq '^[0-9a-f]{64}$' "$key"
[ "$(stat -c '%a' "$key")" = 600 ]
dash -n "$openwrt"

echo "ok setup"
