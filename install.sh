#!/bin/sh
set -eu

PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin
destdir=${DESTDIR:-}
root=${destdir}/opt
tmp_binary=$root/sbin/.keensteerd.$$
tmp_init=$root/etc/init.d/.S99keensteer.$$
tmp_setup=$root/sbin/.keensteer-setup.$$

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
if [ -e "$root/etc/keensteer.conf" ]; then
	had_config=1
fi
if [ -z "$destdir" ] && pidof keensteerd >/dev/null 2>&1; then
	was_running=1
fi

if [ ! -x keensteerd ]; then
	echo "Prebuilt target binary not found: ./keensteerd" >&2
	exit 1
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

trap 'rm -f "$tmp_binary" "$tmp_init" "$tmp_setup"' EXIT
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
if [ ! -e "$root/etc/keensteer.conf" ]; then
	cp files/keensteer.conf "$root/etc/keensteer.conf"
	chmod 0600 "$root/etc/keensteer.conf"
fi
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
	echo "Created $root/etc/keensteer.conf"
	if [ -z "$destdir" ]; then
		echo "Run $root/sbin/keensteer-setup to configure roaming."
	fi
fi
