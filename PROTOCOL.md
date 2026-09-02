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

EtherType `0xeeee` signal `0x50` has an 11-byte body. The receive ifindex selects the source BSS and the STA starts at frame offset `0x34`. A query clears PMKR0Name and supplies the configured local R0KH-ID and actual target R1KH-ID. The tested `FT_QueryKeyInfoForKDP()` overwrites the response R0KH-ID from the selected BSS; it must equal the request identity, which detects selection of another local BSS.

Signal `0xa0` carries a target cache-miss element at `0x32`. The tested constructor zeroes the element, then writes the header, STA, nonzero PMKR0Name, target R1KH and equal S1KH. It does not populate R0KH MAC or R0KH-ID. A request without R0KH-ID is sent to each configured compatible R0 peer, bounded by the peer and pending-table limits; the first authenticated matching response consumes the group. A variant supplying a nonzero R0KH-ID must match exactly one configured peer. Signal `0xa1` carries correlation bytes at `0x2e` and the response element at `0x32`. It must match correlation, source ifindex, STA, S1KH, local R0KH-ID, local R0KH MAC, target R1KH and deadline before it is consumed.

The wrapper IPv4 is configured trusted peer metadata. For `0x8409`, mtkiappd also sends an opaque native duplicate to that IPv4 on TCP/3517; the configured sink must accept, drain and close without interpreting it. Sinks are rechecked one at a time every 30 seconds in both states. For `0x840a`, the same IPv4 records the actual OpenWrt R0/source owner.

The AF_PACKET socket uses `ETH_P_ALL` because that is the observation path validated on the tested firmware. keensteer does not register as mtkiappd or bndstrg.

The tested 112-byte BNDSTRG message stores band at offset 4, RSSI samples at
71..73, STA at 88, and `CLI_UPDATE` connection state at 95. Band 1 is 5 GHz
and band 2 is 2.4 GHz. Because no BSS identity is present, a band with more
than one active configured BSS is rejected as ambiguous. WEXT registered and
expired events use their netlink ifindex directly.

## hostapd RRB

RRB uses EtherType `0x88b7`, OUI wrapper `00 13 74 00 01`, and subtype 1 through 5 for PULL, RESP, PUSH, SEQ_REQ and SEQ_RESP. The body is a little-endian authenticated-TLV length, authenticated TLVs, a 16-byte AES-SIV tag, and encrypted TLVs.

PULL authenticated TLVs are NONCE, SEQ, R0KH-ID and R1KH-ID; PMKR0Name and S1KH-ID are encrypted. RESP authenticates the same identities and nonce, and encrypts S1KH-ID, PMK-R1, PMKR1Name, pairwise and lifetime. PUSH authenticates SEQ, R0KH-ID and R1KH-ID and additionally encrypts PMKR0Name. AES-SIV associated data is source Ethernet MAC, the complete authenticated TLV bytes, then the subtype byte.

Hostapd legacy 16-byte RKH keys are expanded as the first HMAC-SHA256 block over `FT OLDKEY`, including its terminating NUL, followed by counter byte 1. A native 32-byte RKH key is used directly, matching current hostapd's fixed key storage.

Sequence state is bounded per configured peer. Timestamps use monotonic seconds, the replay backlog is 16 sequence numbers, unknown domains or ambiguous windows trigger authenticated SEQ_REQ/SEQ_RESP synchronization, and duplicates/old values are rejected. Pending frames and nonces expire after ten seconds.

An authenticated RESP containing S1KH-ID but none of PMK-R1, PMKR1Name,
pairwise or expiry is a hostapd cache miss. It clears the matching pending
PULL without issuing `0x840a`. If any of those four fields is present, all
four must be present once with the exact expected lengths; partial, duplicate
or malformed records are rejected.
