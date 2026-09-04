#!/bin/sh
set -eu

destdir=${DESTDIR:-}
root=${destdir}/opt

if [ "$#" -ne 0 ]; then
	echo "usage: $0" >&2
	exit 2
fi
if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh must run as root" >&2
	exit 1
fi
if [ ! -d "$root" ]; then
	echo "Entware root not found: $root" >&2
	exit 1
fi

if [ -z "$destdir" ] && [ -x "$root/etc/init.d/S99keensteer" ]; then
	"$root/etc/init.d/S99keensteer" stop >/dev/null 2>&1 || true
fi
rm -f "$root/sbin/keensteerd" "$root/sbin/keensteer-setup" \
	"$root/etc/init.d/S99keensteer" "$root/etc/keensteer-openwrt.sh"
echo "Removed keensteer and its init script."
echo "Configuration and keys were preserved."
