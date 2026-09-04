#!/bin/sh
set -eu

die()
{
	echo "keensteer OpenWrt setup: $*" >&2
	exit 1
}

replace_entry()
{
	wifi=$1
	option=$2
	prefix=$3
	value=$4
	for old in $(uci -q get "wireless.$wifi.$option" || true); do
		case "$old" in
			"$prefix"*) uci -q del_list "wireless.$wifi.$option=$old" || true ;;
		esac
	done
	uci add_list "wireless.$wifi.$option=$value"
}

remove_owner()
{
	wifi=$1
	owner=$2
	for option in r0kh r1kh; do
		for old in $(uci -q get "wireless.$wifi.$option" || true); do
			case "$old" in
				"$owner,"*) uci -q del_list "wireless.$wifi.$option=$old" || true ;;
			esac
		done
	done
}

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -n "${listen_ip:-}" ] || die "listen_ip missing"
[ -n "${mobility_domain:-}" ] || die "mobility_domain missing"
[ -n "${rrb_key:-}" ] || die "rrb_key missing"
[ -n "${keenetic_mac:-}" ] || die "keenetic_mac missing"
[ -n "${keenetic_bss:-}" ] || die "keenetic_bss missing"
[ -n "${interfaces:-}" ] || die "interfaces missing"
peers=${peers:-}
networks=

if ! command -v socat >/dev/null 2>&1; then
	if command -v apk >/dev/null 2>&1; then
		apk update
		apk add socat
	else
		opkg update
		opkg install socat
	fi
fi
command -v socat >/dev/null 2>&1 || die "socat is not installed"

for entry in $interfaces; do
	wifi=${entry%%|*}
	rest=${entry#*|}
	nasid=${rest%%|*}
	bssid=${rest#*|}

	[ "$(uci -q get "wireless.$wifi")" = "wifi-iface" ] ||
		die "wireless.$wifi is not a Wi-Fi interface"
	uci set "wireless.$wifi.ieee80211r=1"
	uci set "wireless.$wifi.ieee80211k=1"
	uci set "wireless.$wifi.bss_transition=1"
	uci set "wireless.$wifi.mobility_domain=$mobility_domain"
	uci set "wireless.$wifi.ft_over_ds=0"
	uci set "wireless.$wifi.ft_psk_generate_local=0"
	uci set "wireless.$wifi.pmk_r1_push=0"
	uci set "wireless.$wifi.nasid=$nasid"
	uci set "wireless.$wifi.r1_key_holder=$nasid"
	remove_owner "$wifi" "$keenetic_mac"
	networks="$networks $(uci -q get "wireless.$wifi.network" || true)"

	for keenetic in $keenetic_bss; do
		keenetic_bssid=${keenetic%%|*}
		keenetic_r0kh=${keenetic#*|}
		replace_entry "$wifi" r0kh "$keenetic_mac,$keenetic_r0kh," "$keenetic_mac,$keenetic_r0kh,$rrb_key"
		replace_entry "$wifi" r1kh "$keenetic_mac,$keenetic_bssid," "$keenetic_mac,$keenetic_bssid,$rrb_key"
	done

	for peer in $peers; do
		peer_bssid=${peer%%|*}
		peer_nasid=${peer#*|}
		[ "$peer_bssid" = "$bssid" ] && continue
		replace_entry "$wifi" r0kh "$peer_bssid,$peer_nasid," "$peer_bssid,$peer_nasid,$rrb_key"
		replace_entry "$wifi" r1kh "$peer_bssid,$peer_bssid," "$peer_bssid,$peer_bssid,$rrb_key"
	done
done

uci commit wireless
wifi reload
if uci -q get usteer.@usteer[-1] >/dev/null 2>&1; then
	for network in $networks; do
		uci -q get usteer.@usteer[-1].network | grep -qw "$network" ||
			{ uci add_list "usteer.@usteer[-1].network=$network"; usteer_changed=1; }
	done
	if [ "${usteer_changed:-0}" = 1 ]; then
		uci commit usteer
		/etc/init.d/usteer restart
	fi
fi

tmp=/etc/init.d/.keensteer-rrb-sink.$$
cat > "$tmp" <<INIT
#!/bin/sh /etc/rc.common

START=90
USE_PROCD=1

start_service()
{
	procd_open_instance
	procd_set_param command /usr/bin/socat "TCP-LISTEN:3517,bind=$listen_ip,reuseaddr,fork" /dev/null
	procd_set_param respawn 3600 5 0
	procd_close_instance
}
INIT

chmod 0755 "$tmp"
mv -f "$tmp" /etc/init.d/keensteer-rrb-sink
/etc/init.d/keensteer-rrb-sink enable
if /etc/init.d/keensteer-rrb-sink status >/dev/null 2>&1; then
	/etc/init.d/keensteer-rrb-sink restart
else
	/etc/init.d/keensteer-rrb-sink start
fi

echo "Configured OpenWrt for keensteer."
