# Setup

The guided setup is the normal installation path. The manual steps below do the same work without the helper.

Keenetic writes the Mobility Domain as two ASCII characters. OpenWrt writes the same two bytes as four hexadecimal digits. For example, Keenetic KN is OpenWrt 4b4e.

# Guided setup

Install keensteer on the Keenetic, then run:

```sh
./install.sh
/opt/sbin/keensteer-setup
```

The helper discovers the active Keenetic radios and asks for the OpenWrt IPv4 address and Mobility Domain.

It connects to OpenWrt over SSH, finds every enabled access point using the same SSID and configures all matching 2.4 GHz and 5 GHz interfaces for 802.11r. OpenWrt radios using other SSIDs are left alone.

The helper preserves an existing key or generates a new one, configures the matching R0KH and R1KH entries on OpenWrt, installs the TCP/3517 listener and writes /opt/etc/keensteer.conf.

Root SSH access from the Keenetic to OpenWrt is required for guided setup. Use the manual setup below if SSH is unavailable.


# Manual setup

The examples use:

| Value | Example |
| --- | --- |
| Keenetic roaming interface | br0 |
| Keenetic 2.4 GHz BSSID | 02:00:00:00:00:10 |
| Keenetic 5 GHz BSSID | 02:00:00:00:00:21 |
| Keenetic RRB MAC | 02:00:00:00:00:10 |
| OpenWrt Wi-Fi section | default_radio1 |
| OpenWrt BSSID | 02:00:00:00:00:20 |
| OpenWrt IPv4 address | 192.0.2.20 |
| Mobility Domain | KN / 4b4e |

Replace every example value with the value from your network.

## 1. Find the Keenetic values

The native band-steering configuration lists the roaming interface and participating Wi-Fi interfaces:

```sh
cat /var/run/bndstrg-br0.conf
```

Read their MAC addresses:

```sh
for i in br0 ra0 ra8; do
	printf '%-5s ' "$i"
	cat "/sys/class/net/$i/address"
done
```

Read the current SSID, channel and bandwidth:

```sh
ndmc -c 'show interface WifiMaster0'
ndmc -c 'show interface WifiMaster1'
ndmc -c 'show interface WifiMaster0/AccessPoint0'
ndmc -c 'show interface WifiMaster1/AccessPoint0'
```

Each Keenetic BSS also needs its native R0KH ID:

```text
Keenetic:<device FT MAC>-00   2.4 GHz
Keenetic:<device FT MAC>-10   5 GHz
```

The device FT MAC is the roaming interface MAC incremented by one. The setup helper derives it. Do not copy the example IDs below; use the values from your router.

## 2. Enable FT on the Keenetic

Use the same two-character Mobility Domain on each participating Keenetic access point:

```sh
ndmc -c 'interface WifiMaster0/AccessPoint0 ft enable'
ndmc -c 'interface WifiMaster0/AccessPoint0 ft mdid KN'
ndmc -c 'interface WifiMaster1/AccessPoint0 ft enable'
ndmc -c 'interface WifiMaster1/AccessPoint0 ft mdid KN'
ndmc -c 'system configuration save'
```

Leave Keenetic's built-in roaming services enabled.

## 3. Find the OpenWrt values

Set the Wi-Fi section and find its live interface:

```sh
WIFI='default_radio1'
RADIO="$(uci -q get wireless.$WIFI.device)"

ubus call network.wireless status | \
	jsonfilter -e "@.$RADIO.interfaces[@.section='$WIFI'].ifname"
```

Use the returned interface name to read the BSSID. For example:

```sh
IFNAME='phy1-ap0'
cat "/sys/class/net/$IFNAME/address"
```

Read the LAN address used by the Keenetic to reach OpenWrt:

```sh
ip -4 addr show br-lan
```

On the tested OpenWrt AP, hostapd sends and receives RRB frames using the participating Wi-Fi BSSID. Do not replace it with the br-lan MAC. If another OpenWrt target uses a different Ethernet identity for RRB, that actual identity belongs in ft_peer instead.

## 4. Generate the shared key

Generate a 32-byte key on either router:

```sh
umask 077
openssl rand -hex 32 > /tmp/keensteer.rrb.key
```

If OpenSSL is unavailable:

```sh
umask 077
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > /tmp/keensteer.rrb.key
echo >> /tmp/keensteer.rrb.key
```

Copy the file to the Keenetic as:

```text
/opt/etc/keensteer.rrb.key
```

Then set its permissions:

```sh
chmod 600 /opt/etc/keensteer.rrb.key
```

The same key is entered in the OpenWrt R0KH and R1KH lists. It is not the Wi-Fi password.

## 5. Configure OpenWrt 802.11r

In LuCI, open:

**Network → Wireless → Edit → WLAN Roaming**

Set:

| LuCI field | Value |
| --- | --- |
| 802.11r Fast Transition | enabled |
| NAS ID | OpenWrt BSSID without colons |
| Mobility Domain | the four hexadecimal digits matching the Keenetic value |
| FT protocol | Over the Air |
| Generate PMK locally | disabled |
| R1 Key Holder | OpenWrt BSSID without colons |
| PMK R1 Push | disabled |

For an OpenWrt BSSID of 02:00:00:00:00:20, both the NAS ID and R1 Key Holder are 020000000020.

The equivalent UCI settings are:

```sh
WIFI='default_radio1'

uci set wireless.$WIFI.ieee80211r='1'
uci set wireless.$WIFI.nasid='020000000020'
uci set wireless.$WIFI.mobility_domain='4b4e'
uci set wireless.$WIFI.ft_over_ds='0'
uci set wireless.$WIFI.ft_psk_generate_local='0'
uci set wireless.$WIFI.r1_key_holder='020000000020'
uci set wireless.$WIFI.pmk_r1_push='0'
```

If the roaming fields are missing in LuCI, install a wpad package with WPA3/SAE and 802.11r support, such as wpad-basic-openssl.

## 6. Add the OpenWrt R0KH and R1KH entries

The two lists describe opposite directions:

- External R0 Key Holder List: where OpenWrt requests a key when a client came from the Keenetic
- External R1 Key Holder List: where OpenWrt sends a key when a client is moving to the Keenetic

For every Keenetic BSS, add one entry to each list.

In LuCI, each R0KH entry is:

```text
<Keenetic RRB MAC>,<Keenetic R0KH ID>,<shared key>
```

Each R1KH entry is:

```text
<Keenetic RRB MAC>,<Keenetic BSSID/R1KH ID>,<same shared key>
```

The equivalent UCI commands for the two example Keenetic BSSes are:

```sh
WIFI='default_radio1'
RRB_KEY="$(cat /tmp/keensteer.rrb.key)"
KEENETIC_MAC='02:00:00:00:00:10'

uci add_list wireless.$WIFI.r0kh="$KEENETIC_MAC,Keenetic:02:00:00:00:00:11-00,$RRB_KEY"
uci add_list wireless.$WIFI.r0kh="$KEENETIC_MAC,Keenetic:02:00:00:00:00:11-10,$RRB_KEY"

uci add_list wireless.$WIFI.r1kh="$KEENETIC_MAC,02:00:00:00:00:10,$RRB_KEY"
uci add_list wireless.$WIFI.r1kh="$KEENETIC_MAC,02:00:00:00:00:21,$RRB_KEY"

uci commit wireless
unset RRB_KEY
wifi reload
```

The R0KH IDs above are only examples. Use the exact IDs from the Keenetic.

## 7. Start the TCP/3517 listener

Keenetic's native roaming service opens an extra TCP connection during the key exchange. The listener only accepts and discards that connection.

Install socat:

```sh
opkg update
opkg install socat
```

On an apk-based OpenWrt release, use apk update and apk add socat instead.

In LuCI, open **System → Startup → Local Startup** and add this before `exit 0`:

```sh
/usr/bin/socat 'TCP-LISTEN:3517,bind=192.0.2.20,reuseaddr,fork' /dev/null &
```

Replace 192.0.2.20 with the OpenWrt address used in the keensteer peer entry, then start it now without rebooting:

```sh
/usr/bin/socat 'TCP-LISTEN:3517,bind=192.0.2.20,reuseaddr,fork' /dev/null &
```

## 8. Configure keensteer

Edit /opt/etc/keensteer.conf on the Keenetic:

```conf
interface=br0

usteer=1
usteer_interval=1000

ft=1
rrb_key_file=/opt/etc/keensteer.rrb.key

bss=ra0,keenetic.2g,example-wifi,02:00:00:00:00:10,6,81,,Keenetic:02:00:00:00:00:11-00
bss=ra8,keenetic.5g,example-wifi,02:00:00:00:00:21,44,128,,Keenetic:02:00:00:00:00:11-10

ft_peer=02:00:00:00:00:20,02:00:00:00:00:20,192.0.2.20,02:00:00:00:00:20,020000000020
```

Each bss line contains:

```text
ifname,node-name,ssid,bssid,channel,opclass,r1kh-id,r0kh-id
```

The R1KH ID may be left empty to use the BSSID.

Each ft_peer line contains:

```text
bssid,rrb-mac,ipv4,r1kh-id,r0kh-id
```

For OpenWrt, the R0KH ID is the NAS ID. The R1KH ID is normally the BSSID. The RRB MAC is the Ethernet identity hostapd actually uses for RRB frames; on the tested OpenWrt AP it is also the BSSID.

## 9. Start and check

On OpenWrt:

```sh
netstat -lnt 2>/dev/null | grep ':3517'
```

On the Keenetic:

```sh
/opt/etc/init.d/S99keensteer restart
/opt/sbin/keensteerd -V
ndmc -c 'show log' | grep -i keensteer | tail -n 30
```

The daemon should start with FT enabled and without a TCP/3517 warning.
