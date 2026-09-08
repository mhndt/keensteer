#!/bin/sh
set -eu

PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin
destdir=${DESTDIR:-}
root=${destdir}/opt
tmp_binary=$root/sbin/.keensteerd.$$
tmp_init=$root/etc/init.d/.S99keensteer.$$
tmp_setup=$root/sbin/.keensteer-setup.$$
tmp_openwrt=$root/etc/.keensteer-openwrt.sh.$$
tmp_example=$root/etc/.keensteer.conf.example.$$
tmp_hdr=$root/etc/.keensteer-hdr.$$

if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
	echo "install.sh must run as root" >&2
	exit 1
fi
if [ ! -d "$root" ]; then
	echo "Entware root not found: $root" >&2
	exit 1
fi
if [ ! -d "$root/etc/init.d" ]; then
	echo "Entware init directory not found: $root/etc/init.d" >&2
	exit 1
fi

had_config=0
was_running=0
stock_home=0
if [ -e "$root/etc/keensteer.conf" ] &&
   cmp -s "$root/etc/keensteer.conf" files/keensteer.conf; then
	stock_home=1
fi
for c in "$root/etc/keensteer.conf" "$root"/etc/keensteer-*.conf; do
	if [ "$stock_home" -eq 1 ] && [ "$c" = "$root/etc/keensteer.conf" ]; then
		continue
	fi
	if [ -e "$c" ]; then
		had_config=1
		break
	fi
done
if [ -z "$destdir" ] && pidof keensteerd >/dev/null 2>&1; then
	was_running=1
fi

if [ ! -x keensteerd ]; then
	echo "Prebuilt target binary not found: ./keensteerd" >&2
	exit 1
fi
elf_arch() {
	{ dd if="$1" bs=1 skip=5 count=1; dd if="$1" bs=1 skip=18 count=2; } > "$tmp_hdr" 2>/dev/null
	if printf '\002\000\010' | cmp -s - "$tmp_hdr"; then echo mips
	elif printf '\001\010\000' | cmp -s - "$tmp_hdr"; then echo mipsel
	elif printf '\001\267\000' | cmp -s - "$tmp_hdr"; then echo aarch64
	else echo unknown
	fi
}
if [ -x "$root/bin/opkg" ]; then
	want=$(elf_arch "$root/bin/opkg")
	have=$(elf_arch keensteerd)
	rm -f "$tmp_hdr"
	if [ "$want" != unknown ] && [ "$have" != unknown ] && [ "$want" != "$have" ]; then
		echo "wrong architecture, use $want" >&2
		exit 1
	fi
fi

if [ -z "$destdir" ] && [ ! -e "$root/lib/libcrypto.so.3" ]; then
	echo "Installing libopenssl..."
	opkg update >/dev/null 2>&1 || true
	if ! opkg install libopenssl; then
		echo "Cannot install libopenssl; run: opkg install libopenssl" >&2
		exit 1
	fi
fi

if ! ./keensteerd -V >/dev/null 2>&1; then
	echo "./keensteerd is not runnable on this target; is libopenssl installed?" >&2
	exit 1
fi

trap 'rm -f "$tmp_binary" "$tmp_init" "$tmp_setup" "$tmp_openwrt" "$tmp_example"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
mkdir -p "$root/sbin" "$root/etc"
cp keensteerd "$tmp_binary"
chmod 0755 "$tmp_binary"
mv -f "$tmp_binary" "$root/sbin/keensteerd"
cp files/S99keensteer "$tmp_init"
chmod 0755 "$tmp_init"
mv -f "$tmp_init" "$root/etc/init.d/S99keensteer"
cp files/keensteer-setup "$tmp_setup"
chmod 0755 "$tmp_setup"
mv -f "$tmp_setup" "$root/sbin/keensteer-setup"
cp files/keensteer-openwrt.sh "$tmp_openwrt"
chmod 0644 "$tmp_openwrt"
mv -f "$tmp_openwrt" "$root/etc/keensteer-openwrt.sh"
cp files/keensteer.conf "$tmp_example"
chmod 0644 "$tmp_example"
mv -f "$tmp_example" "$root/etc/keensteer.conf.example"
[ "$stock_home" -eq 0 ] || rm -f "$root/etc/keensteer.conf"
trap - EXIT

echo "Installed $root/sbin/keensteerd"
if [ "$had_config" -eq 1 ]; then
	echo "Existing configuration and keys were preserved."
	if [ -z "$destdir" ] && [ "$was_running" -eq 1 ]; then
		"$root/etc/init.d/S99keensteer" restart
	elif [ -z "$destdir" ]; then
		echo "Start with: $root/etc/init.d/S99keensteer start"
	fi
else
	echo "Installed $root/etc/keensteer.conf.example"
	if [ -z "$destdir" ]; then
		[ "$was_running" -eq 0 ] || "$root/etc/init.d/S99keensteer" stop >/dev/null 2>&1 || true
		echo "Run $root/sbin/keensteer-setup to configure roaming."
	fi
fi
