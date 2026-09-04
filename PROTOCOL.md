# Protocol notes

This file records only the wire and private-ABI assumptions implemented by keensteer. Multi-byte packet fields are read and written bytewise.

## usteer remote node

UDP port 16720 carries libubox blob attributes. Top-level IDs are `ID=0`, `SEQ=1`, `NODES=2`, and optional `HOST_INFO=3`. Each node publishes name, SSID, frequency, noise, load, association counts, BSSID, channel, operating class, Neighbor Report and stations using the current upstream IDs.

The Neighbor Report is a 13-byte hex string inside the blobmsg array shape used by usteer: BSSID, a conservative zero BSSID Information field, operating class, channel and PHY type.

Classic station IDs are:

```text
0 addr(binary6)  1 signal(int32)  2 timeout(int32)
3 seen(int32)    4 connected(int8)  5 last_connected(int32)
```

usteer-ng assigns ID 5 to `seen_2ghz`, ID 6 to `seen_5ghz`, and ID 7 to `last_connected`. The encoder emits both typed ID 5 attributes. libubox `blob_parse_attr()` ignores a type mismatch and accepts the later matching attribute, while IDs outside a parser's policy range are ignored. Tests verify both mappings and malformed outer lengths.

## MediaTek KDP

The private WEXT command is `0x8be1`. It is callable on the tested driver but
is not listed by `SIOCGIWPRIV`, so that inventory is not a capability gate.
There is no non-mutating KDP probe; real request failures are rejected without
classifying the vendor return through errno. Source query OID `0x8409` and
insert OID `0x840a` use a 179-byte buffer: four correlation/source IPv4 bytes,
eight wrapper bytes, then the 167-byte element.

```text
00  2  ff ff
02  2  00 a3
04  3  00 0e 2e
07  6  STA
10 48  R0KH-ID storage
40  1  R0KH-ID length
41 16  PMKR0Name
51  6  target R1KH-ID
57  6  S1KH-ID
61 16  PMKR1Name
71 32  PMK-R1
91  6  R0KH BSSID/MAC
97  4  pairwise selector
9b  4  AKM selector
9f  4  remaining lifetime
a3  4  reassociation value
```

The supported selectors are `00 0f ac 04` (CCMP) and `00 0f ac 09` (FT-SAE). The tested insert uses reassociation value 20.

EtherType `0xeeee` signal `0x50` has an 11-byte body. The receive ifindex selects the source BSS and the STA starts at frame offset `0x34`. The prewarm query generated from signal `0x50` clears PMKR0Name and supplies the configured local R0KH-ID and actual target R1KH-ID. The ioctl interface supplies the initial BSS, but a normal live station entry overrides it with the station's BSS index. `FT_QueryKeyInfoForKDP()` looks up the type-1 cache entry by effective BSS and STA; zero PMKR0Name accepts that entry and nonzero PMKR0Name must match it exactly. Request R0KH-ID is not a lookup key. The response R0KH-ID is overwritten from the effective BSS and must equal the request identity, which detects selection of another local BSS.

Signal `0xa0` carries a target cache-miss element at `0x32`. The tested constructor zeroes the element, then writes the header, STA, nonzero PMKR0Name, target R1KH and equal S1KH. It does not populate R0KH MAC or R0KH-ID. A request without R0KH-ID is sent to each configured compatible R0 peer, bounded by the peer and pending-table limits; the first authenticated matching response consumes the group. A variant supplying a nonzero R0KH-ID must match exactly one configured peer. Signal `0xa1` carries correlation bytes at `0x2e` and the response element at `0x32`. It must match correlation, source ifindex, STA, S1KH, local R0KH-ID, local R0KH MAC, target R1KH and deadline before it is consumed.

OID `0x840e` (neighbor report `0x040e` with the `0x8000` set toggle, as mtkiappd issues it) inserts or withdraws an FT neighbor through the same private ioctl. Its 29-byte payload is the peer IPv4, the neighbor BSSID, four BSSID-information bytes, operating class, channel, PHY type, two mobility-domain bytes, a present flag, state 2, a changed flag and empty access-list counts; the driver stores the entry only when `rrm` is enabled on the interface. keensteer sends it when usteer first reports a valid channel and operating class for an OpenWrt peer or either changes, retrying failed updates, and withdraws it when the peer expires, retrying until the withdrawal succeeds. A driver that rejects the OID as unsupported disables neighbor reports only. The Keenetic builds its 802.11k neighbor reports from its scan table, so a neighbor missing there makes the driver survey that channel once, immediately when the band has no clients and otherwise deferred until it is idle, which lets clients learn about the OpenWrt access points.

The wrapper IPv4 is configured trusted peer metadata. For `0x8409`, mtkiappd also sends an opaque native duplicate to that IPv4 on TCP/3517; the configured sink must accept, drain and close without interpreting it. Sinks are rechecked one at a time every 30 seconds in both states. For `0x840a`, the same IPv4 records the actual OpenWrt R0/source owner.

MediaTek ioctl `0x8bea` returns an eight-byte per-radio channel-utilization record. Byte 1 is the bandwidth enum, byte 2 is the primary channel, byte 3 is the secondary or center channel and byte 6 is channel load in percent. keensteer samples it every three seconds and accepts values only when the returned length, bandwidth, primary channel and percentage are valid; otherwise load is zero. A primary channel that differs from the discovered one makes keensteer rediscover the interfaces once before deciding, because channel changes such as DFS moves raise no link event. Bandwidth values 0 to 3 (20, 40, 80 and 160 MHz) also refresh the operating class of the interface, with byte 3 deciding whether a 40 MHz secondary channel lies above or below the primary; other values leave it unchanged.

MediaTek ioctl `0x8bef` (`get_mac_table`, listed by `SIOCGIWPRIV`) returns the associated client table of the queried AP interface as text: a header line naming the columns, then one row per station in associated state, starting with the station MAC as twelve hex digits, the MediaTek BSS index in the `AP` column and the averaged per-antenna RSSI in dBm in the `RSSI` column. The tested driver requires a buffer of at least 841 bytes, writes 140-byte rows, stops once fewer than 140 bytes remain and replaces the final newline with NUL. keensteer queries every active BSS about once a minute and reads only the MAC, `AP` and `RSSI` columns. A plausible RSSI refreshes the station signal and seen time, because BNDSTRG does not continuously report RSSI for settled associated stations. The result is applied only when every query succeeded, every row parsed, each interface reported one distinct BSS index and no station appeared twice; otherwise station state is left unchanged until the next interval. WEXT, BNDSTRG and KDP events remain the immediate update path. A missing `get_mac_table` or an unrecognized header disables reconciliation only.

The AF_PACKET socket uses `ETH_P_ALL` because that is the observation path validated on the tested firmware; the driver injects KDP events as received frames on the BSS interface. A socket filter passes only received `0xeeee` and `0x88b7` frames to userspace. keensteer does not register as mtkiappd or bndstrg.

The tested 112-byte BNDSTRG message stores band at offset 4, RSSI samples at
71..73, STA at 88, and `CLI_UPDATE` connection state at 95. Band 1 is 5 GHz
and band 2 is 2.4 GHz. Because no BSS identity is present, a band with more
than one active configured BSS is rejected as ambiguous. WEXT registered and
expired events use their netlink ifindex directly.

## hostapd RRB

RRB uses EtherType `0x88b7`, OUI wrapper `00 13 74 00 01`, and subtype 1 through 5 for PULL, RESP, PUSH, SEQ_REQ and SEQ_RESP. The body is a little-endian authenticated-TLV length, authenticated TLVs, a 16-byte AES-SIV tag, and encrypted TLVs.

PULL authenticated TLVs are NONCE, SEQ, R0KH-ID and R1KH-ID; PMKR0Name and S1KH-ID are encrypted. RESP authenticates the same identities and nonce, and encrypts S1KH-ID, PMK-R1, PMKR1Name, pairwise and lifetime. PUSH authenticates SEQ, R0KH-ID and R1KH-ID and additionally encrypts PMKR0Name. AES-SIV associated data is source Ethernet MAC, the complete authenticated TLV bytes, then the subtype byte.

An incoming PULL selects one configured peer by source MAC and R1KH-ID and one local BSS by R0KH-ID. After replay acceptance, its exact nonzero PMKR0Name and S1KH-ID are submitted through `0x8409` on that BSS and the response checks fail closed if the driver selects another BSS. The pending KDP tuple is source BSS, peer, STA and target R1KH; retries with the same nonce are deduplicated and conflicting requests do not replace it. A matching `0xa1` sends RESP instead of PUSH.

Hostapd legacy 16-byte RKH keys are expanded as the first HMAC-SHA256 block over `FT OLDKEY`, including its terminating NUL, followed by counter byte 1. A native 32-byte RKH key is used directly, matching current hostapd's fixed key storage.

Sequence state is bounded per configured peer. Timestamps use monotonic seconds, the replay backlog is 16 sequence numbers, unknown domains or ambiguous windows trigger authenticated SEQ_REQ/SEQ_RESP synchronization, and duplicates/old values are rejected. Pending frames and nonces expire after ten seconds.

An authenticated RESP containing S1KH-ID but none of PMK-R1, PMKR1Name,
pairwise or expiry is a hostapd cache miss. It clears the matching pending
PULL without issuing `0x840a`. If any of those four fields is present, all
four must be present once with the exact expected lengths; partial, duplicate
or malformed records are rejected.

For an incoming PULL, synchronous `0x8409` failure or expiry produces the same S1KH-only RESP. A positive response echoes the PULL nonce and identities and uses a fresh transmit sequence.
