#define _GNU_SOURCE
#include "keensteer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); return -1; } } while (0)

#define BLOB_LEN_MASK 0x00ffffffu
#define BLOB_ID_SHIFT 24

struct attr {
	unsigned int id;
	const uint8_t *data;
	size_t len;
};

static bool mock_wext;
static bool mock_load_error;
static uint8_t mock_load[8];
static uint16_t mock_load_len;
static unsigned int mock_load_calls;
static int mock_freq_channel = 44;
static bool mock_priv_error, mock_priv_missing;
static struct { char ifname[IFNAMSIZ]; const char *text; bool error; } mock_table[2];
static uint16_t mock_table_len;
static unsigned int mock_table_calls;

int __real_ioctl(int fd, unsigned long request, ...);
int __wrap_ioctl(int fd, unsigned long request, ...);

int __wrap_ioctl(int fd, unsigned long request, ...)
{
	struct iwreq *wrq;
	va_list ap;

	va_start(ap, request); wrq = va_arg(ap, struct iwreq *); va_end(ap);
	if (!mock_wext) return __real_ioctl(fd, request, wrq);
	(void) fd;
	switch (request) {
	case SIOCGIFHWADDR:
		memcpy(wrq->u.ap_addr.sa_data,
		       (uint8_t[]) { 0x02, 0x10, 0x20, 0x30, 0x40, 0x50 }, 6);
		return 0;
	case SIOCGIFINDEX:
		((struct ifreq *) wrq)->ifr_ifindex = 1;
		return 0;
	case SIOCGIWMODE:
		wrq->u.mode = IW_MODE_MASTER;
		return 0;
	case SIOCGIWESSID:
		memcpy(wrq->u.essid.pointer, "live-ess", 8);
		wrq->u.essid.length = 8;
		return 0;
	case SIOCGIWFREQ:
		wrq->u.freq.m = mock_freq_channel;
		wrq->u.freq.e = 0;
		return 0;
	case SIOCGIWPRIV: {
		struct iw_priv_args *a = wrq->u.data.pointer;

		if (mock_priv_error) { errno = ENODEV; return -1; }
		a[0].cmd = SIOCIWFIRSTPRIV + 2; strcpy(a[0].name, "set");
		a[1].cmd = KS_MTK_MAC_TABLE_IOCTL; strcpy(a[1].name, "get_mac_table");
		wrq->u.data.length = mock_priv_missing ? 1 : 2;
		return 0;
	}
	case KS_MTK_MAC_TABLE_IOCTL: {
		size_t i, n;

		mock_table_calls++;
		for (i = 0; i < 2; i++)
			if (mock_table[i].text && !strcmp(mock_table[i].ifname, wrq->ifr_name)) break;
		if (i == 2 || mock_table[i].error) { errno = EOPNOTSUPP; return -1; }
		n = strlen(mock_table[i].text);
		if (n > wrq->u.data.length) n = wrq->u.data.length;
		memcpy(wrq->u.data.pointer, mock_table[i].text, n);
		if (n) ((uint8_t *) wrq->u.data.pointer)[n - 1] = 0;
		wrq->u.data.length = mock_table_len ? mock_table_len : (uint16_t) n;
		return 0;
	}
	case KS_MTK_LOAD_IOCTL:
		mock_load_calls++;
		if (mock_load_error) { errno = EOPNOTSUPP; return -1; }
		memcpy(wrq->u.data.pointer, mock_load, sizeof(mock_load));
		wrq->u.data.length = mock_load_len;
		return 0;
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}

static size_t pad4(size_t n)
{
	return (n + 3) & ~3u;
}

static int next_attr(const uint8_t *buf, size_t len, size_t *off, struct attr *a)
{
	uint32_t h;
	size_t raw, padded;

	if (*off > len || len - *off < 4) return -1;
	h = ks_get_be32(buf + *off);
	raw = h & BLOB_LEN_MASK;
	padded = pad4(raw);
	if (raw < 4 || padded > len - *off) return -1;
	a->id = (h >> BLOB_ID_SHIFT) & 0x7f;
	a->data = buf + *off + 4;
	a->len = raw - 4;
	*off += padded;
	return 0;
}

static int find_attr(const uint8_t *buf, size_t len, unsigned int id,
		     size_t exact, struct attr *out)
{
	struct attr a;
	size_t off = 0;

	while (off < len) {
		if (next_attr(buf, len, &off, &a)) return -1;
		if (a.id == id && (!exact || a.len == exact)) {
			*out = a;
			return 1;
		}
	}
	return 0;
}

static int hex(const char *s, uint8_t *out, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		unsigned int v;
		if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t) v;
	}
	return 0;
}

static int put_tlv(uint8_t *buf, size_t cap, size_t *len, uint16_t type,
		   const void *data, size_t n)
{
	if (n > UINT16_MAX || cap - *len < n + 4) return -1;
	ks_put_le16(buf + *len, type);
	ks_put_le16(buf + *len + 2, (uint16_t) n);
	if (n) memcpy(buf + *len + 4, data, n);
	*len += n + 4;
	return 0;
}

static int get_tlv(const uint8_t *buf, size_t len, uint16_t type,
		   const uint8_t **data, size_t *data_len)
{
	int found = 0;
	while (len) {
		uint16_t t, n;
		if (len < 4) return -1;
		t = ks_get_le16(buf); n = ks_get_le16(buf + 2); buf += 4; len -= 4;
		if (n > len) return -1;
		if (t == type) {
			if (found) return -1;
			*data = buf; *data_len = n; found = 1;
		}
		buf += n; len -= n;
	}
	return found;
}

static void kdp_request(struct ks_kdp_element *e, const uint8_t sta[6],
			const uint8_t *r0, size_t r0n, const uint8_t n0[16],
			const uint8_t r1[6])
{
	memset(e, 0, sizeof(*e));
	memcpy(e->raw, "\xff\xff\x00\xa3\x00\x0e\x2e", 7);
	memcpy(e->raw + 0x07, sta, 6);
	if (r0n) memcpy(e->raw + 0x10, r0, r0n);
	e->raw[0x40] = (uint8_t) r0n;
	memcpy(e->raw + 0x41, n0, 16);
	memcpy(e->raw + 0x51, r1, 6);
	memcpy(e->raw + 0x57, sta, 6);
}

static int pull_frame(const uint8_t key[32], const uint8_t src[6],
		      const uint8_t dst[6], const uint8_t nonce[16],
		      const uint8_t seq[12], const uint8_t *r0, size_t r0n,
		      const uint8_t r1[6], const uint8_t n0[16],
		      const uint8_t sta[6], uint8_t *frame, size_t *flen)
{
	uint8_t auth[256], plain[128];
	size_t alen = 0, plen = 0;

	if (put_tlv(auth, sizeof(auth), &alen, 2, nonce, 16) ||
	    put_tlv(auth, sizeof(auth), &alen, 1, seq, 12) ||
	    put_tlv(auth, sizeof(auth), &alen, 4, r0, r0n) ||
	    put_tlv(auth, sizeof(auth), &alen, 5, r1, 6) ||
	    put_tlv(plain, sizeof(plain), &plen, 7, n0, 16) ||
	    put_tlv(plain, sizeof(plain), &plen, 6, sta, 6)) return -1;
	return ks_rrb_build(1, src, dst, key, auth, alen, plain, plen,
			    frame, 768, flen);
}

static void sample_state(struct ks_state *s, unsigned int nodes)
{
	static const uint8_t bssid[][6] = {
		{ 0x02, 0x10, 0x20, 0x30, 0x40, 0x50 },
		{ 0x02, 0x10, 0x20, 0x30, 0x40, 0x51 }
	};
	struct ks_station *st;
	uint64_t now = ks_now_ms();
	unsigned int i;

	memset(s, 0, sizeof(*s));
	ks_config_defaults(&s->cfg);
	s->usteer_id = 0x11223344;
	s->cfg.n_bss = nodes;
	for (i = 0; i < nodes; i++) {
		struct ks_bss *b = &s->cfg.bss[i];
		b->active = true;
		snprintf(b->name, sizeof(b->name), "keenetic.ap%u", i);
		strcpy(b->ssid, "test-ess");
		memcpy(b->bssid, bssid[i], 6);
		memcpy(b->r1kh_id, bssid[i], 6);
		b->freq = i ? 5180 : 2412;
		b->channel = i ? 36 : 1;
		b->op_class = i ? 115 : 81;
		b->band = i ? KS_BAND_5GHZ : KS_BAND_2GHZ;
		b->noise = 0;
		b->load = 0;
		b->max_assoc = 0;
	}
	st = &s->stations[0];
	st->used = st->connected = st->seen_2ghz = true;
	memcpy(st->addr, (uint8_t[]) { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, 6);
	st->bss_index = 0;
	st->signal[0] = -51;
	st->seen_ms[0] = now - 25;
	st->connected_ms = now - 100;
}

static int first_station(const uint8_t *buf, size_t len, struct attr *station,
			 struct attr *node)
{
	struct attr root, nodes, stations;
	size_t off = 0;

	if (next_attr(buf, len, &off, &root) || off != len ||
	    find_attr(root.data, root.len, 2, 0, &nodes) != 1) return -1;
	off = 0;
	if (next_attr(nodes.data, nodes.len, &off, node) ||
	    find_attr(node->data, node->len, 3, 0, &stations) != 1) return -1;
	off = 0;
	return next_attr(stations.data, stations.len, &off, station);
}

static int test_usteer(void)
{
	struct ks_state tx, rx;
	struct attr sta, node, a, rrm, array, str;
	struct sockaddr_in src = { .sin_family = AF_INET };
	uint8_t buf[KS_MAX_PACKET], copy[KS_MAX_PACKET];
	size_t len, off;
	uint64_t now = ks_now_ms();
	unsigned int nodes = 0;

	sample_state(&tx, 2);
	tx.cfg.bss[0].load = 37;
	CHECK(!ks_usteer_encode(&tx, buf, sizeof(buf), &len));
	CHECK(!first_station(buf, len, &sta, &node));
	CHECK(find_attr(sta.data, sta.len, 0, 6, &a) == 1);
	CHECK(find_attr(sta.data, sta.len, 1, 4, &a) == 1 && (int32_t) ks_get_be32(a.data) == -51);
	CHECK(find_attr(sta.data, sta.len, 2, 4, &a) == 1);
	CHECK(find_attr(sta.data, sta.len, 3, 4, &a) == 1);
	CHECK(find_attr(sta.data, sta.len, 4, 1, &a) == 1 && a.data[0] == 1);
	CHECK(find_attr(sta.data, sta.len, 5, 4, &a) == 1 && ks_get_be32(a.data) == 0);
	CHECK(find_attr(sta.data, sta.len, 5, 1, &a) == 1 && a.data[0] == 1);
	CHECK(find_attr(sta.data, sta.len, 6, 1, &a) == 1 && a.data[0] == 0);
	CHECK(find_attr(sta.data, sta.len, 7, 4, &a) == 1 && ks_get_be32(a.data) == 0);
	CHECK(find_attr(node.data, node.len, 4, 4, &a) == 1 && ks_get_be32(a.data) == 0);
	CHECK(find_attr(node.data, node.len, 5, 4, &a) == 1 && ks_get_be32(a.data) == 37);
	CHECK(find_attr(node.data, node.len, 7, 4, &a) == 1 && ks_get_be32(a.data) == 0);
	CHECK(find_attr(node.data, node.len, 8, 0, &rrm) == 1);
	off = 0;
	CHECK(!next_attr(rrm.data, rrm.len, &off, &array) && array.id == 1 && array.len >= 4);
	off = 0;
	CHECK(!next_attr(array.data + 4, array.len - 4, &off, &str) && str.id == 3 && str.len > 4);
	CHECK(str.data[4 + 12] == '0' && str.data[4 + 13] == '0');

	memset(&rx, 0, sizeof(rx));
	ks_config_defaults(&rx.cfg);
	rx.usteer_id = 7;
	rx.cfg.n_ft_peers = 1;
	rx.cfg.ft_peers[0].used = true;
	memcpy(rx.cfg.ft_peers[0].bssid, tx.cfg.bss[0].bssid, 6);
	CHECK(inet_pton(AF_INET, "192.0.2.22", &src.sin_addr) == 1);
	rx.cfg.ft_peers[0].peer_ip = src.sin_addr;
	rx.cfg.n_bss = 1; rx.cfg.bss[0].active = rx.cfg.bss[0].mtk_kdp = true;
	strcpy(rx.cfg.bss[0].ifname, "ra0"); rx.ioctl_fd = -2; ks_mtk_test_reset();
	CHECK(ks_usteer_parse(&rx, buf, len, &src, now) == 2);
	CHECK(rx.cfg.ft_peers[0].learned && !strcmp(rx.cfg.ft_peers[0].ssid, "test-ess"));
	{
		uint8_t rec[64]; size_t rlen; uint16_t oid; int bss; unsigned int n_ioctl;
		struct ks_ft_peer *p = &rx.cfg.ft_peers[0];

		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 1);
		CHECK(!ks_mtk_test_last_ioctl(&oid, &bss, rec, sizeof(rec), &rlen));
		CHECK(oid == KS_OID_FT_NEIGHBOR && bss == 0 && rlen == 29);
		CHECK(!memcmp(rec, &src.sin_addr.s_addr, 4) && !memcmp(rec + 4, tx.cfg.bss[0].bssid, 6));
		CHECK(rec[0x0e] == 81 && rec[0x0f] == 1 && rec[0x10] == 7 && rec[0x13] == 1 &&
		      rec[0x14] == 2 && rec[0x15] == 1 && !rec[0x1b] && !rec[0x1c]);
		CHECK(p->neighbor_channel == 1 && p->neighbor_op_class == 81);
		CHECK(ks_usteer_parse(&rx, buf, len, &src, now) == 2);
		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 1);
		/* a failed update keeps the installed record known */
		tx.cfg.bss[0].channel = 6; rx.ioctl_fd = -1;
		CHECK(!ks_usteer_encode(&tx, copy, sizeof(copy), &rlen));
		CHECK(ks_usteer_parse(&rx, copy, rlen, &src, now) == 2);
		CHECK(p->channel == 6 && p->neighbor_channel == 1);
		rx.ioctl_fd = -2;
		CHECK(ks_usteer_parse(&rx, copy, rlen, &src, now) == 2 && p->neighbor_channel == 6);
		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 2);
		CHECK(!ks_mtk_test_last_ioctl(&oid, &bss, rec, sizeof(rec), &rlen) && rec[0x0f] == 6);
		/* an invalid operating class is not sent and does not disturb the installed record */
		tx.cfg.bss[0].op_class = 300;
		CHECK(!ks_usteer_encode(&tx, copy, sizeof(copy), &rlen));
		CHECK(ks_usteer_parse(&rx, copy, rlen, &src, now) == 2);
		CHECK(p->op_class == 300 && p->neighbor_channel == 6 && p->neighbor_op_class == 81);
		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 2);
		tx.cfg.bss[0].op_class = 81; tx.cfg.bss[0].channel = 1;
		/* a failed withdrawal is retried until it succeeds */
		p->last_seen_ms = now - rx.cfg.peer_ttl_ms; rx.ioctl_fd = -1;
		ks_usteer_expire(&rx, now);
		CHECK(!p->learned && !p->channel && p->neighbor_channel == 6);
		ks_usteer_expire(&rx, now);
		CHECK(p->neighbor_channel == 6);
		rx.ioctl_fd = -2;
		ks_usteer_expire(&rx, now);
		CHECK(!p->neighbor_channel && !p->neighbor_op_class);
		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 3);
		CHECK(!ks_mtk_test_last_ioctl(&oid, &bss, rec, sizeof(rec), &rlen) && rlen == 29 &&
		      !rec[0x13] && rec[0x0f] == 6 && rec[0x0e] == 81);
		/* an unsupported OID disables neighbor reports only */
		tx.cfg.bss[0].channel = 11;
		CHECK(!ks_usteer_encode(&tx, copy, sizeof(copy), &rlen));
		rx.ioctl_fd = 1; mock_wext = true;
		CHECK(ks_usteer_parse(&rx, copy, rlen, &src, now) == 2);
		mock_wext = false;
		CHECK(rx.neighbor_off && p->learned && !p->neighbor_channel && rx.cfg.usteer_enabled);
		rx.ioctl_fd = -2;
		CHECK(ks_usteer_parse(&rx, copy, rlen, &src, now) == 2 && !p->neighbor_channel);
		ks_mtk_test_counts(NULL, &n_ioctl); CHECK(n_ioctl == 3);
		rx.neighbor_off = false; tx.cfg.bss[0].channel = 1;
	}

	off = 0;
	CHECK(!next_attr(buf, len, &off, &a));
	CHECK(find_attr(a.data, a.len, 2, 0, &a) == 1);
	off = 0;
	while (off < a.len) { CHECK(!next_attr(a.data, a.len, &off, &node)); nodes++; }
	CHECK(nodes == 2);
	for (off = 0; off < len; off++) CHECK(ks_usteer_parse(&rx, buf, off, &src, now) < 0);
	memcpy(copy, buf, len);
	for (off = 0; off < 512; off++) {
		size_t pos = (off * 1103515245u + 12345u) % len;
		copy[pos] ^= (uint8_t) (1u << (off & 7));
		(void) ks_usteer_parse(&rx, copy, len, &src, now);
		copy[pos] = buf[pos];
	}
	tx.cfg.station_ttl_ms = 20;
	ks_station_expire(&tx, ks_now_ms() + 100);
	CHECK(tx.stations[0].used && tx.stations[0].connected && !tx.stations[0].seen_ms[0]);
	return 0;
}

static int test_aes_siv(void)
{
	uint8_t key[32], ad0[24], plain[32], want[30], out[64], dec[64];
	const uint8_t *ad[] = { ad0 };
	size_t ad_len[] = { 24 };

	CHECK(!hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key, 32));
	CHECK(!hex("101112131415161718191a1b1c1d1e1f2021222324252627", ad0, 24));
	CHECK(!hex("112233445566778899aabbccddee", plain, 14));
	CHECK(!hex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c", want, 30));
	CHECK(!ks_aes_siv_encrypt(key, plain, 14, ad, ad_len, 1, out));
	CHECK(!memcmp(out, want, 30));
	CHECK(!ks_aes_siv_decrypt(key, out, 30, ad, ad_len, 1, dec));
	CHECK(!memcmp(dec, plain, 14));
	out[0] ^= 1;
	CHECK(ks_aes_siv_decrypt(key, out, 30, ad, ad_len, 1, dec));
	return 0;
}

static int test_key_expansion(void)
{
	uint8_t old[16], out[32], want[32];
	char path[] = "/tmp/keensteer-key-XXXXXX";
	char err[128];
	int fd;

	CHECK(!hex("000102030405060708090a0b0c0d0e0f", old, 16));
	CHECK(!hex("19dafc5c6b21def65f42f15bc967aa63777ba7553557803d6849fc947ef66ff7", want, 32));
	CHECK(!ks_rrb_expand_key(old, out) && !memcmp(out, want, 32));
	fd = mkstemp(path);
	CHECK(fd >= 0);
	CHECK(write(fd, "000102030405060708090a0b0c0d0e0f\n", 33) == 33);
	CHECK(!fchmod(fd, 0600));
	CHECK(!ks_load_rrb_key(path, out, err, sizeof(err)) && !memcmp(out, want, 32));
	CHECK(!fchmod(fd, 0644));
	CHECK(ks_load_rrb_key(path, out, err, sizeof(err)) < 0);
	CHECK(!unlink(path));
	CHECK(!close(fd));
	return 0;
}

static int test_config(void)
{
	static const char good[] =
		"interface=eth0\n"
		"usteer=1\n"
		"ft=1\n"
		"bss=wlan0,node,ess,02:00:00:00:00:10,36,128,,keenetic-r0\n"
		"ft_peer=02:00:00:00:00:20,02:00:00:00:00:21,192.0.2.20,,remote-r0\n";
	static const char bad[] =
		"interface=eth0\n"
		"bss=wlan0,node,ess,02:00:00:00:00:10,36,128,,keenetic-r0\n"
		"ft=1\n"
		"ft_peer=02:00:00:00:00:20,02:00:00:00:00:21,127.0.0.1,,remote-r0\n";
	static const char duplicate[] =
		"interface=eth0\n"
		"bss=wlan0,node,ess,02:00:00:00:00:10,36,128,,keenetic-r0\n"
		"ft=1\n"
		"ft_peer=02:00:00:00:00:20,02:00:00:00:00:21,192.0.2.20,,remote-r0\n"
		"ft_peer=02:00:00:00:00:30,02:00:00:00:00:31,192.0.2.30,,remote-r0\n";
	static const char duplicate_local[] =
		"interface=eth0\n"
		"ft=1\n"
		"bss=wlan0,node0,ess,02:00:00:00:00:10,1,81,,keenetic-r0\n"
		"bss=wlan1,node1,ess,02:00:00:00:00:11,36,115,,keenetic-r0\n"
		"ft_peer=02:00:00:00:00:20,02:00:00:00:00:21,192.0.2.20,,remote-r0\n";
	struct ks_config cfg;
	char path[] = "/tmp/keensteer-config-XXXXXX", err[128];
	int fd = mkstemp(path);

	CHECK(fd >= 0); ks_config_defaults(&cfg); CHECK(!cfg.transport_if[0]);
	CHECK(write(fd, good, sizeof(good) - 1) == (ssize_t) sizeof(good) - 1);
	CHECK(!close(fd));
	CHECK(!ks_config_load(&cfg, path, err, sizeof(err)));
	CHECK(!strcmp(cfg.transport_if, "eth0") && cfg.n_bss == 1 &&
	      cfg.n_ft_peers == 1 && cfg.ft_peers[0].r0kh_id_len == 9 &&
	      cfg.bss[0].r0kh_id_len == 11 && !cfg.bss[0].noise &&
	      !cfg.bss[0].load && !cfg.bss[0].max_assoc);
	fd = open(path, O_WRONLY | O_TRUNC);
	CHECK(fd >= 0 && write(fd, bad, sizeof(bad) - 1) == (ssize_t) sizeof(bad) - 1);
	CHECK(!close(fd)); ks_config_defaults(&cfg);
	CHECK(ks_config_load(&cfg, path, err, sizeof(err)) < 0);
	fd = open(path, O_WRONLY | O_TRUNC);
	CHECK(fd >= 0 && write(fd, duplicate, sizeof(duplicate) - 1) ==
	      (ssize_t) sizeof(duplicate) - 1);
	CHECK(!close(fd)); ks_config_defaults(&cfg);
	CHECK(ks_config_load(&cfg, path, err, sizeof(err)) < 0);
	fd = open(path, O_WRONLY | O_TRUNC);
	CHECK(fd >= 0 && write(fd, duplicate_local, sizeof(duplicate_local) - 1) ==
	      (ssize_t) sizeof(duplicate_local) - 1);
	CHECK(!close(fd)); ks_config_defaults(&cfg);
	CHECK(ks_config_load(&cfg, path, err, sizeof(err)) < 0);
	CHECK(!unlink(path));
	ks_config_defaults(&cfg);
	CHECK(!ks_config_load(&cfg, "files/keensteer.conf", err, sizeof(err)) &&
	      cfg.n_bss == 1 && !cfg.ft_enabled);
	{
		struct ks_state s;
		struct ks_bss *b;

		memset(&s, 0, sizeof(s)); ks_config_defaults(&s.cfg);
		strcpy(s.cfg.transport_if, "lo"); s.cfg.n_bss = 1; b = &s.cfg.bss[0];
		strcpy(b->ifname, "lo"); strcpy(b->name, "node"); strcpy(b->ssid, "ess");
		memcpy(b->bssid, (uint8_t[]) { 0x02, 0, 0, 0, 0, 1 }, 6);
		memcpy(b->r1kh_id, b->bssid, 6); b->channel = 36; b->freq = 5180;
		b->op_class = 128; b->band = KS_BAND_5GHZ;
		mock_wext = true; CHECK(!ks_topology_discover(&s)); mock_wext = false;
		CHECK(b->active && b->mtk_kdp && b->channel == 44 &&
		      !strcmp(b->ssid, "live-ess") && !b->noise && !b->load &&
		      !b->max_assoc);
		memcpy(mock_load, (uint8_t[]) { 1, 0, 44, 149, 0, 1, 37, 0 }, 8);
		mock_load_len = 8; mock_load_error = false; mock_load_calls = 0;
		s.ioctl_fd = 1; s.next_load_ms = 0; mock_wext = true;
		ks_backend_update_load(&s);
		CHECK(b->load == 37 && mock_load_calls == 1 && b->op_class == 115);
		ks_backend_update_load(&s); CHECK(mock_load_calls == 1);
		s.next_load_ms = 0; mock_load[2] = 36; ks_backend_update_load(&s);
		CHECK(!b->load);
		s.next_load_ms = 0; mock_load[2] = 44; mock_load[1] = 5;
		ks_backend_update_load(&s); CHECK(!b->load);
		s.next_load_ms = 0; mock_load[1] = 2; mock_load[6] = 101;
		ks_backend_update_load(&s); CHECK(!b->load);
		s.next_load_ms = 0; mock_load[6] = 12; mock_load_len = 7;
		ks_backend_update_load(&s); CHECK(!b->load);
		s.next_load_ms = 0; mock_load_len = 8; mock_load_error = true;
		ks_backend_update_load(&s); CHECK(!b->load);
		mock_load_error = false; s.next_load_ms = 0; mock_load[2] = 36; mock_freq_channel = 36;
		ks_backend_update_load(&s);
		CHECK(b->load == 12 && b->channel == 36 && b->freq == 5180 && b->active);
		s.next_load_ms = 0; mock_load[2] = 40; ks_backend_update_load(&s);
		CHECK(!b->load && b->channel == 36 && b->op_class == 128);
		s.next_load_ms = 0; mock_load[2] = 36; mock_load[1] = 1; mock_load[3] = 40;
		ks_backend_update_load(&s); CHECK(b->load == 12 && b->op_class == 116);
		s.next_load_ms = 0; mock_load[3] = 32; ks_backend_update_load(&s);
		CHECK(b->op_class == 117);
		s.next_load_ms = 0; mock_load[3] = 0; ks_backend_update_load(&s);
		CHECK(b->op_class == 116);
		s.next_load_ms = 0; mock_load[1] = 3; ks_backend_update_load(&s);
		CHECK(b->op_class == 129);
		s.next_load_ms = 0; mock_load[1] = 4; ks_backend_update_load(&s);
		CHECK(b->load == 12 && b->op_class == 129);
		s.next_load_ms = 0; mock_load[1] = 0; ks_backend_update_load(&s);
		CHECK(b->op_class == 115);
		CHECK(ks_opclass(6, 40, 10) == 83 && ks_opclass(6, 40, 2) == 84 &&
		      ks_opclass(6, 40, 0) == 83 && ks_opclass(11, 40, 0) == 84);
		CHECK(ks_opclass(1, 20, 0) == 81 && ks_opclass(14, 20, 0) == 82 &&
		      ks_opclass(14, 40, 0) == 82 && ks_opclass(165, 40, 0) == 125);
		CHECK(ks_opclass(100, 80, 0) == 128 && ks_opclass(149, 160, 0) == 129 &&
		      ks_opclass(6, 80, 0) == 81 && !ks_opclass(0, 20, 0) && !ks_opclass(200, 20, 0));
		CHECK(ks_opclass(153, 40, 0) == 127 && ks_opclass(157, 40, 0) == 126 &&
		      ks_opclass(64, 40, 0) == 120 && ks_opclass(140, 40, 0) == 122 &&
		      ks_opclass(144, 40, 0) == 123 && ks_opclass(100, 40, 0) == 122);
		CHECK(ks_opclass_width(129) == 160 && ks_opclass_width(128) == 80 &&
		      ks_opclass_width(122) == 40 && ks_opclass_width(81) == 20);
		mock_freq_channel = 44;
		mock_wext = false;
	}
	{
		struct ks_state s;
		struct ks_bss *b;
		struct { struct nlmsghdr nh; struct ifinfomsg ifi; } msg;
		int sv[2];

		memset(&s, 0, sizeof(s)); ks_config_defaults(&s.cfg);
		strcpy(s.cfg.transport_if, "lo"); s.cfg.n_bss = 1; b = &s.cfg.bss[0];
		strcpy(b->ifname, "lo"); strcpy(b->name, "node"); strcpy(b->ssid, "ess");
		memcpy(b->bssid, (uint8_t[]) { 0x02, 0, 0, 0, 0, 1 }, 6);
		memcpy(b->r1kh_id, b->bssid, 6); b->channel = 36; b->freq = 5180;
		b->op_class = 128; b->band = KS_BAND_5GHZ;
		s.transport_ifindex = 1; s.ioctl_fd = 1;
		CHECK(!socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
		s.netlink_fd = sv[0];
		memset(&msg, 0, sizeof(msg));
		msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifi));
		msg.nh.nlmsg_type = RTM_NEWLINK;
		msg.ifi.ifi_index = 99;
		CHECK(!ks_active_bss(&s));
		mock_wext = true;
		CHECK(send(sv[1], &msg, sizeof(msg), 0) == (ssize_t) sizeof(msg));
		CHECK(ks_backend_handle_netlink(&s) == 1 && b->active && b->channel == 44 &&
		      ks_active_bss(&s) == 1);
		mock_freq_channel = 48;
		CHECK(send(sv[1], &msg, sizeof(msg), 0) == (ssize_t) sizeof(msg));
		CHECK(ks_backend_handle_netlink(&s) == 1 && b->active && b->channel == 44);
		msg.ifi.ifi_index = 1;
		CHECK(send(sv[1], &msg, sizeof(msg), 0) == (ssize_t) sizeof(msg));
		CHECK(ks_backend_handle_netlink(&s) == 1 && b->active && b->channel == 48);
		s.cfg.n_bss = 2; s.cfg.bss[1] = *b; strcpy(s.cfg.bss[1].name, "node2");
		s.cfg.bss[1].active = false; mock_freq_channel = 52; msg.ifi.ifi_index = 99;
		CHECK(send(sv[1], &msg, sizeof(msg), 0) == (ssize_t) sizeof(msg));
		CHECK(ks_backend_handle_netlink(&s) == 1 && ks_active_bss(&s) == 2 && b->channel == 52);
		mock_freq_channel = 56;
		CHECK(send(sv[1], &msg, sizeof(msg), 0) == (ssize_t) sizeof(msg));
		CHECK(ks_backend_handle_netlink(&s) == 1 && b->channel == 52);
		mock_freq_channel = 44;
		mock_wext = false;
		close(sv[0]); close(sv[1]);
	}
	return 0;
}

static int test_kdp(void)
{
	uint8_t sta[6] = { 0x02, 1, 2, 3, 4, 5 };
	uint8_t r1[6] = { 0x02, 6, 7, 8, 9, 10 };
	uint8_t r1b[6] = { 0x02, 6, 7, 8, 9, 11 };
	uint8_t r0mac[6] = { 0x02, 11, 12, 13, 14, 15 };
	uint8_t n0[16], n1[16], key[32], wrapper[KS_KDP_WRAPPER_LEN];
	uint8_t f50[61] = {0}, fa0[217] = {0}, fa1[217] = {0}, parsed_sta[6];
	uint8_t bnd[112] = {0}, bnd_mac[6];
	struct ks_kdp_element e, request, response, assoc, parsed;
	struct ks_state s;
	uint16_t oid;
	uint32_t corr = htonl(0x7f000001u), got;
	size_t i, r0n, ioctl_len;
	unsigned int rrb_count, ioctl_count;
	int signal, ioctl_bss;
	const uint8_t *r0;

	for (i = 0; i < sizeof(n0); i++) n0[i] = (uint8_t) (i + 1);
	for (i = 0; i < sizeof(n1); i++) n1[i] = (uint8_t) (i + 0x21);
	for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t) (i + 0x41);
	CHECK(!ks_kdp_from_rrb(&e, sta, (uint8_t *) "r0-test", 7, n0, r1, n1,
			       key, r0mac, 0x10, 120));
	CHECK(!ks_kdp_parse_element(e.raw, sizeof(e.raw), &parsed));
	r0 = ks_kdp_r0kh_id(&parsed, &r0n);
	CHECK(r0n == 7 && !memcmp(r0, "r0-test", 7));
	CHECK(ks_kdp_lifetime(&parsed) == 120);
	CHECK(!ks_kdp_build_wrapper(corr, &e, wrapper));
	CHECK(!memcmp(wrapper, &corr, 4) && !memcmp(wrapper + 12, e.raw, sizeof(e.raw)));

	f50[12] = f50[13] = 0xee; f50[0x20] = 0x50;
	ks_put_be32(f50 + 0x2a, 11); memcpy(f50 + 0x34, sta, 6);
	CHECK(!ks_kdp_parse_signal50(f50, sizeof(f50), 3, &assoc, parsed_sta));
	CHECK(!memcmp(sta, parsed_sta, 6));
	for (i = 0; i < sizeof(f50); i++) CHECK(ks_kdp_parse_signal50(f50, i, 3, &parsed, parsed_sta) < 0);
	f50[0x20] = 0x51; CHECK(ks_kdp_parse_signal50(f50, sizeof(f50), 3, &parsed, parsed_sta) < 0);

	fa1[12] = fa1[13] = 0xee; fa1[0x20] = 0xa1;
	ks_put_be32(fa1 + 0x2a, KS_KDP_ELEMENT_LEN);
	memcpy(fa1 + 0x2e, &corr, 4); memcpy(fa1 + 0x32, e.raw, sizeof(e.raw));
	CHECK(!ks_kdp_parse_signala1(fa1, sizeof(fa1), &got, &parsed));
	CHECK(got == corr && !memcmp(parsed.raw, e.raw, sizeof(e.raw)));
	for (i = 0; i < sizeof(fa1); i++) CHECK(ks_kdp_parse_signala1(fa1, i, &got, &parsed) < 0);
	fa1[0x32 + 0x40] = 49;
	CHECK(ks_kdp_parse_signala1(fa1, sizeof(fa1), &got, &parsed) < 0);

	fa0[12] = fa0[13] = 0xee; fa0[0x20] = 0xa0;
	ks_put_be32(fa0 + 0x2a, KS_KDP_ELEMENT_LEN);
	kdp_request(&request, sta, NULL, 0, n0, r1);
	memcpy(fa0 + 0x32, request.raw, sizeof(request.raw));
	CHECK(!ks_kdp_parse_signala0(fa0, sizeof(fa0), &parsed));
	CHECK(!memcmp(parsed.raw, request.raw, sizeof(request.raw)));
	fa0[0x32] ^= 1;
	CHECK(!ks_kdp_parse_signala0(fa0, sizeof(fa0), &parsed));
	fa0[0x32] ^= 1;
	for (i = 0; i < sizeof(fa0); i++) CHECK(ks_kdp_parse_signala0(fa0, i, &parsed) < 0);
	fa0[0x32 + 0x91] = 2;
	CHECK(!ks_kdp_parse_signala0(fa0, sizeof(fa0), &parsed));
	fa0[0x32 + 0x91] = 0; fa0[0x32 + 0x57] ^= 2;
	CHECK(ks_kdp_parse_signala0(fa0, sizeof(fa0), &parsed) < 0);
	fa0[0x32 + 0x57] ^= 2;
	fa0[0x20] = 0xa1; CHECK(ks_kdp_parse_signala0(fa0, sizeof(fa0), &parsed) < 0);

	bnd[0] = 0x15; bnd[71] = (uint8_t) -70; bnd[72] = (uint8_t) -55;
	bnd[73] = (uint8_t) -80; memcpy(bnd + 88, sta, 6);
	CHECK(!ks_mtk_test_bndstrg(bnd, sizeof(bnd), bnd_mac, &signal));
	CHECK(signal == -55 && !memcmp(bnd_mac, sta, 6));
	CHECK(ks_mtk_test_bndstrg(bnd, sizeof(bnd) - 1, bnd_mac, &signal) < 0);
	CHECK(!ks_mtk_test_bndstrg(bnd, 104, bnd_mac, &signal) && signal == -55);
	CHECK(ks_mtk_test_bndstrg(bnd, 103, bnd_mac, &signal) < 0);
	bnd[0] = 2; CHECK(ks_mtk_test_bndstrg(bnd, sizeof(bnd), bnd_mac, &signal) < 0);
	bnd[0] = 1; bnd[88] |= 1;
	CHECK(ks_mtk_test_bndstrg(bnd, sizeof(bnd), bnd_mac, &signal) < 0);

	memset(&s, 0, sizeof(s));
	ks_config_defaults(&s.cfg); s.cfg.ft_enabled = true; s.rrb_key_loaded = true;
	s.packet_fd = s.ioctl_fd = -2; s.transport_ifindex = 1; s.cfg.n_bss = 1;
	s.cfg.bss[0].active = s.cfg.bss[0].mtk_kdp = true; s.cfg.bss[0].ifindex = 9;
	memcpy(s.cfg.bss[0].bssid, r0mac, 6); memcpy(s.cfg.bss[0].r0kh_id, "keenetic-r0", 11);
	s.cfg.bss[0].r0kh_id_len = 11;
	s.cfg.n_ft_peers = 1; s.cfg.ft_peers[0].used = s.cfg.ft_peers[0].sink_ready = true;
	memcpy(s.cfg.ft_peers[0].r1kh_id, r1, 6);
	memcpy(s.cfg.ft_peers[0].transport, (uint8_t[]) { 0x02, 9, 8, 7, 6, 5 }, 6);
	memcpy(s.cfg.ft_peers[0].r0kh_id, "remote", 6);
	s.cfg.ft_peers[0].r0kh_id_len = 6;
	s.cfg.ft_peers[0].peer_ip.s_addr = corr;
	CHECK(ks_kdp_prewarm_event(&s, 0, &assoc) == 1);
	CHECK(!ks_mtk_test_last_ioctl(&oid, &ioctl_bss, wrapper, sizeof(wrapper), &ioctl_len));
	CHECK(oid == KS_OID_FT_QUERY && ioctl_bss == 0 && ioctl_len == sizeof(wrapper));
	CHECK(!memcmp(wrapper, &corr, 4) && !memcmp(wrapper + 4, (uint8_t[8]) {0}, 8));
	CHECK(!memcmp(wrapper + 12, "\xff\xff\x00\xa3\x00\x0e\x2e", 7));
	CHECK(!memcmp(wrapper + 12 + 0x07, sta, 6));
	CHECK(wrapper[12 + 0x40] == 11 &&
	      !memcmp(wrapper + 12 + 0x10, "keenetic-r0", 11));
	CHECK(!memcmp(wrapper + 12 + 0x10 + 11, (uint8_t[37]) {0}, 37));
	CHECK(!memcmp(wrapper + 12 + 0x41, (uint8_t[16]) {0}, 16));
	CHECK(!memcmp(wrapper + 12 + 0x51, r1, 6) &&
	      !memcmp(wrapper + 12 + 0x57, sta, 6));
	CHECK(!memcmp(wrapper + 12 + 0x61, (uint8_t[70]) {0}, 70));
	CHECK(!ks_kdp_from_rrb(&response, sta, (uint8_t *) "keenetic-r0", 11,
			       n0, r1, n1, key, r0mac, 0x10, 120));
	CHECK(!ks_kdp_handle_response(&s, 8, corr, &response) && s.kdp_pending[0].used);
	CHECK(!ks_kdp_handle_response(&s, 9, corr ^ 1, &response) && s.kdp_pending[0].used);
	CHECK(!ks_kdp_handle_response(&s, 9, corr, &response) && !s.kdp_pending[0].used);
	CHECK(ks_kdp_prewarm_event(&s, 0, &assoc) == 1);
	response.raw[0x10] ^= 1;
	CHECK(ks_kdp_handle_response(&s, 9, corr, &response) < 0 && !s.kdp_pending[0].used);
	s.kdp_pending[1].used = true; s.kdp_pending[1].deadline_ms = ks_now_ms();
	ks_kdp_expire(&s, ks_now_ms()); CHECK(!s.kdp_pending[1].used);
	s.cfg.n_bss = 2; s.cfg.bss[1] = s.cfg.bss[0];
	s.cfg.bss[1].ifindex = 10;
	memcpy(s.cfg.bss[1].bssid, (uint8_t[]) { 0x02, 11, 12, 13, 14, 16 }, 6);
	memcpy(s.cfg.bss[1].r1kh_id, r1b, 6);
	kdp_request(&request, sta, NULL, 0, n0, r1b);
	memset(request.raw, 0, 7);
	memset(fa0, 0, sizeof(fa0)); fa0[12] = fa0[13] = 0xee; fa0[0x20] = 0xa0;
	ks_put_be32(fa0 + 0x2a, KS_KDP_ELEMENT_LEN);
	memcpy(fa0 + 0x32, request.raw, sizeof(request.raw));
	ks_mtk_test_reset();
	CHECK(ks_mtk_test_packet(&s, fa0, sizeof(fa0), 9) == 1);
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING && s.pull_pending[i].target_bss == 1);
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(rrb_count == 1 && ioctl_count == 0);
	ks_secure_clear(key, sizeof(key));
	return 0;
}

static int test_association(void)
{
	struct ks_state s;
	struct attr station, node, n_assoc;
	uint8_t event[20] = {0};
	uint8_t custom[120] = {0};
	uint8_t wire[KS_MAX_PACKET];
	uint8_t sta[6] = { 0x02, 1, 2, 3, 4, 5 };
	uint8_t other[6] = { 0x02, 6, 7, 8, 9, 10 };
	uint16_t len = sizeof(event), family = 1, cmd, dlen = 112, flags = 0x0950;
	size_t wire_len;

	sample_state(&s, 2); memset(s.stations, 0, sizeof(s.stations));
	s.cfg.bss[0].ifindex = 7; s.cfg.bss[1].ifindex = 8;
	cmd = IWEVREGISTERED;
	memcpy(event, &len, 2); memcpy(event + 2, &cmd, 2);
	memcpy(event + 4, &family, 2); memcpy(event + 6, sta, 6);
	CHECK(ks_mtk_test_wireless(&s, 7, event, sizeof(event)) == 1);
	CHECK(s.stations[0].used && s.stations[0].connected &&
	      s.stations[0].bss_index == 0 && !s.stations[0].seen_ms[0]);
	CHECK(!ks_usteer_encode(&s, wire, sizeof(wire), &wire_len));
	CHECK(first_station(wire, wire_len, &station, &node) < 0);
	CHECK(find_attr(node.data, node.len, 2, 4, &n_assoc) == 1 &&
	      ks_get_be32(n_assoc.data) == 1);
	s.cfg.station_ttl_ms = 20;
	ks_station_expire(&s, ks_now_ms() + 100);
	CHECK(s.stations[0].used && s.stations[0].connected);
	cmd = IWEVEXPIRED; memcpy(event + 2, &cmd, 2);
	CHECK(ks_mtk_test_wireless(&s, 7, event, sizeof(event)) == 1);
	CHECK(!s.stations[0].connected);
	ks_station_expire(&s, ks_now_ms() + 100);
	CHECK(!s.stations[0].used);
	len = sizeof(custom); cmd = IWEVCUSTOM;
	memcpy(custom, &len, 2); memcpy(custom + 2, &cmd, 2);
	memcpy(custom + 4, &dlen, 2); memcpy(custom + 6, &flags, 2);
	custom[8] = 3;
	custom[8 + 4] = 2;
	memcpy(custom + 8 + 88, sta, 6);
	custom[8 + 95] = 1;
	CHECK(ks_mtk_test_wireless(&s, 7, custom, sizeof(custom)) == 1);
	CHECK(s.stations[0].used && s.stations[0].connected &&
	      s.stations[0].bss_index == 0);
	custom[8 + 95] = 0;
	CHECK(ks_mtk_test_wireless(&s, 7, custom, sizeof(custom)) == 1);
	CHECK(!s.stations[0].connected);
	custom[8 + 4] = 1; custom[8 + 95] = 1;
	CHECK(ks_mtk_test_wireless(&s, 7, custom, sizeof(custom)) == 1);
	CHECK(s.stations[0].connected && s.stations[0].bss_index == 1);
	custom[8] = 0x15; custom[8 + 71] = (uint8_t) -65;
	custom[8 + 72] = (uint8_t) -52; custom[8 + 73] = (uint8_t) -80;
	CHECK(ks_mtk_test_wireless(&s, 7, custom, sizeof(custom)) == 1);
	CHECK(s.stations[0].signal[1] == -52 && s.stations[0].seen_ms[1]);
	custom[8 + 4] = 2;
	CHECK(ks_mtk_test_wireless(&s, 8, custom, sizeof(custom)) == 1);
	CHECK(s.stations[0].signal[0] == -52 && s.stations[0].seen_ms[0]);
	s.cfg.bss[0].band = KS_BAND_5GHZ;
	custom[8] = 3; custom[8 + 4] = 1; custom[8 + 95] = 1;
	memcpy(custom + 8 + 88, other, 6);
	CHECK(ks_mtk_test_wireless(&s, 7, custom, sizeof(custom)) == 1);
	CHECK(!ks_station_get(&s, other, false));
	CHECK(ks_mtk_test_wireless(&s, 7, event, sizeof(event) - 1) < 0);
	return 0;
}

static int test_rrb(void)
{
	uint8_t key[32], src[6] = { 0x02, 1, 1, 1, 1, 1 }, dst[6] = { 0x02, 2, 2, 2, 2, 2 };
	uint8_t r1[6] = { 0x02, 3, 3, 3, 3, 3 }, sta[6] = { 0x02, 4, 4, 4, 4, 4 };
	uint8_t seq[12], n0[16], n1[16], pmk[32], pair[2], exp[2];
	uint8_t auth[128], plain[256], frame[768], copy[768];
	struct ks_rrb_message msg;
	struct ks_rrb_plain dec;
	struct ks_state s;
	size_t alen = 0, plen = 0, flen, i;
	unsigned int count;

	for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t) (i + 1);
	for (i = 0; i < sizeof(n0); i++) n0[i] = (uint8_t) (i + 0x20);
	for (i = 0; i < sizeof(n1); i++) n1[i] = (uint8_t) (i + 0x40);
	for (i = 0; i < sizeof(pmk); i++) pmk[i] = (uint8_t) (i + 0x60);
	ks_put_le32(seq, 0x12345679); ks_put_le32(seq + 4, 20);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	ks_put_le16(pair, 0x10); ks_put_le16(exp, 90);
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 7, n0, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 10, pmk, 32));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 9, n1, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 11, pair, 2));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 12, exp, 2));
	CHECK(!ks_rrb_build(3, src, dst, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg));
	CHECK(!ks_rrb_decrypt(key, &msg, &dec));
	CHECK(dec.len == plen && !memcmp(dec.data, plain, plen));
	for (i = 0; i < flen; i++) {
		if (ks_rrb_parse_frame(frame, i, &msg) == 0)
			CHECK(ks_rrb_decrypt(key, &msg, &dec) < 0);
	}
	memcpy(copy, frame, flen); copy[14] ^= 1;
	CHECK(ks_rrb_parse_frame(copy, flen, &msg) < 0);
	memcpy(copy, frame, flen); copy[flen - 1] ^= 1;
	CHECK(!ks_rrb_parse_frame(copy, flen, &msg));
	CHECK(ks_rrb_decrypt(key, &msg, &dec) < 0);

	memset(&s, 0, sizeof(s));
	ks_config_defaults(&s.cfg);
	s.cfg.ft_enabled = true; s.rrb_key_loaded = true;
	memcpy(s.rrb_key, key, sizeof(key)); memcpy(s.transport_mac, dst, 6); s.ioctl_fd = -1;
	s.cfg.n_bss = 1; s.cfg.bss[0].active = s.cfg.bss[0].mtk_kdp = true;
	memcpy(s.cfg.bss[0].bssid, dst, 6); memcpy(s.cfg.bss[0].r1kh_id, r1, 6);
	s.cfg.n_ft_peers = 1; s.cfg.ft_peers[0].used = true;
	memcpy(s.cfg.ft_peers[0].transport, src, 6);
	memcpy(s.cfg.ft_peers[0].r0kh_id, "remote", 6); s.cfg.ft_peers[0].r0kh_id_len = 6;
	s.cfg.ft_peers[0].rx_domain = ks_get_le32(seq);
	s.cfg.ft_peers[0].rx_count = 1; s.cfg.ft_peers[0].rx_last[0] = 19;
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	count = s.cfg.ft_peers[0].rx_count; CHECK(count == 2);
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	CHECK(s.cfg.ft_peers[0].rx_count == count);
	ks_secure_clear(pmk, sizeof(pmk));
	return 0;
}

static int test_rrb_pull_resp(void)
{
	uint8_t key[32], local[6] = { 0x02, 2, 2, 2, 2, 2 };
	uint8_t remote[6] = { 0x02, 1, 1, 1, 1, 1 };
	uint8_t remote_bss[6] = { 0x02, 1, 1, 1, 1, 2 };
	uint8_t r1[6] = { 0x02, 3, 3, 3, 3, 3 }, sta[6] = { 0x02, 4, 4, 4, 4, 4 };
	uint8_t n0[16], n1[16], pmk[32], seq[12], pair[2], exp[2];
	uint8_t auth[256], plain[256], frame[768], wrapper[KS_KDP_WRAPPER_LEN];
	const uint8_t *v;
	struct ks_rrb_message msg;
	struct ks_rrb_plain dec;
	struct ks_kdp_element event, inserted;
	struct ks_state s;
	uint16_t oid;
	int bss;
	size_t alen = 0, plen = 0, flen, n, i;
	unsigned int rrb_count, ioctl_count;

	for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t) (i + 1);
	for (i = 0; i < sizeof(n0); i++) n0[i] = (uint8_t) (i + 0x20);
	for (i = 0; i < sizeof(n1); i++) n1[i] = (uint8_t) (i + 0x40);
	for (i = 0; i < sizeof(pmk); i++) pmk[i] = (uint8_t) (i + 0x60);
	kdp_request(&event, sta, NULL, 0, n0, r1);
	memset(&s, 0, sizeof(s)); ks_config_defaults(&s.cfg);
	s.cfg.ft_enabled = true; s.rrb_key_loaded = true;
	memcpy(s.rrb_key, key, sizeof(key)); memcpy(s.transport_mac, local, 6);
	s.packet_fd = s.ioctl_fd = -2; s.transport_ifindex = 1;
	s.cfg.n_bss = 1; s.cfg.bss[0].active = s.cfg.bss[0].mtk_kdp = true;
	memcpy(s.cfg.bss[0].bssid, local, 6); memcpy(s.cfg.bss[0].r1kh_id, r1, 6);
	s.cfg.n_ft_peers = 1; s.cfg.ft_peers[0].used = true;
	memcpy(s.cfg.ft_peers[0].transport, remote, 6);
	memcpy(s.cfg.ft_peers[0].bssid, remote_bss, 6);
	memcpy(s.cfg.ft_peers[0].r0kh_id, "remote", 6); s.cfg.ft_peers[0].r0kh_id_len = 6;
	CHECK(inet_pton(AF_INET, "192.0.2.22", &s.cfg.ft_peers[0].peer_ip) == 1);
	ks_mtk_test_reset();
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	CHECK(!ks_mtk_test_last_rrb(frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg) && msg.subtype == 1);
	CHECK(get_tlv(msg.auth, msg.auth_len, 4, &v, &n) == 1 && n == 6 &&
	      !memcmp(v, "remote", 6));
	CHECK(!ks_rrb_decrypt(key, &msg, &dec));
	CHECK(get_tlv(dec.data, dec.len, 7, &v, &n) == 1 && n == 16 && !memcmp(v, n0, 16));
	CHECK(get_tlv(dec.data, dec.len, 6, &v, &n) == 1 && n == 6 && !memcmp(v, sta, 6));

	ks_put_le32(seq, 0x12345679); ks_put_le32(seq + 4, 20);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	s.cfg.ft_peers[0].rx_domain = ks_get_le32(seq);
	s.cfg.ft_peers[0].rx_count = 1; s.cfg.ft_peers[0].rx_last[0] = 19;
	ks_put_le16(pair, 0x10); ks_put_le16(exp, 90);
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.pull_pending[0].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 10, pmk, 32));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 9, n1, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 11, pair, 2));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 12, exp, 2));
	CHECK(!ks_rrb_build(2, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!s.pull_pending[0].used);
	CHECK(!ks_mtk_test_last_ioctl(&oid, &bss, wrapper, sizeof(wrapper), &n));
	CHECK(oid == KS_OID_FT_INSERT && bss == 0 && n == sizeof(wrapper));
	CHECK(!memcmp(wrapper, &s.cfg.ft_peers[0].peer_ip.s_addr, 4));
	CHECK(!ks_kdp_parse_element(wrapper + 12, KS_KDP_ELEMENT_LEN, &inserted));
	CHECK(!memcmp(ks_kdp_pmkr0name(&inserted), n0, 16));
	CHECK(!memcmp(ks_kdp_pmkr1name(&inserted), n1, 16));
	CHECK(!memcmp(ks_kdp_pmkr1(&inserted), pmk, 32));
	CHECK(!memcmp(ks_kdp_r0kh_mac(&inserted), remote_bss, 6));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(rrb_count == 1 && ioctl_count == 1);

	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING);
	alen = plen = 0; ks_put_le32(seq + 4, 21);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.pull_pending[i].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!ks_rrb_build(2, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!s.pull_pending[i].used);
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 1);

	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING);
	alen = plen = 0; ks_put_le32(seq + 4, 22);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.pull_pending[i].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 10, pmk, 32));
	CHECK(!ks_rrb_build(2, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	CHECK(!s.pull_pending[i].used);
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 1);

	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING);
	alen = plen = 0; ks_put_le32(seq + 4, 23);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.pull_pending[i].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 9, "x", 1));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 10, "x", 1));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 11, "x", 1));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 12, "x", 1));
	CHECK(!ks_rrb_build(2, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	CHECK(!s.pull_pending[i].used);
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 1);

	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING);
	alen = plen = 0; ks_put_le32(seq + 4, 24);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.pull_pending[i].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, sizeof(seq)));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, "remote", 6));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!ks_rrb_build(2, (uint8_t[]) { 0x02, 9, 9, 9, 9, 9 }, local,
			    key, auth, alen, plain, plen, frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(s.pull_pending[i].used);
	ks_secure_clear(&s.pull_pending[i], sizeof(s.pull_pending[i]));
	s.cfg.n_ft_peers = 2; s.cfg.ft_peers[1] = s.cfg.ft_peers[0];
	memcpy(s.cfg.ft_peers[1].transport, (uint8_t[]) { 0x02, 5, 5, 5, 5, 5 }, 6);
	memcpy(s.cfg.ft_peers[1].r0kh_id, "other", 5); s.cfg.ft_peers[1].r0kh_id_len = 5;
	CHECK(inet_pton(AF_INET, "192.0.2.23", &s.cfg.ft_peers[1].peer_ip) == 1);
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	for (i = n = 0; i < KS_MAX_RRB_PENDING; i++) n += s.pull_pending[i].used;
	CHECK(n == 2);
	ks_rrb_expire(&s, ks_now_ms() + 11000);
	for (i = n = 0; i < KS_MAX_RRB_PENDING; i++) n += s.pull_pending[i].used;
	CHECK(!n);
	ks_secure_clear(pmk, sizeof(pmk));
	return 0;
}

static int test_rrb_incoming_pull(void)
{
	static const char r0[] = "Keenetic:02:00:00:00:00:11-00";
	static const char other_r0[] = "Keenetic:02:00:00:00:00:12-00";
	uint8_t key[32], local[6] = { 0x02, 2, 2, 2, 2, 2 };
	uint8_t local_bss[6] = { 0x02, 2, 2, 2, 2, 3 };
	uint8_t remote[6] = { 0x02, 1, 1, 1, 1, 1 };
	uint8_t remote2[6] = { 0x02, 1, 1, 1, 1, 2 };
	uint8_t r1[6] = { 0x02, 3, 3, 3, 3, 3 };
	uint8_t r1b[6] = { 0x02, 3, 3, 3, 3, 4 };
	uint8_t sta[6] = { 0x02, 4, 4, 4, 4, 4 };
	uint8_t bad_sta[6] = { 0x01, 4, 4, 4, 4, 4 };
	uint8_t nonce[16], nonce2[16], n0[16], n0b[16], n1[16], pmk[32];
	uint8_t seq[12], seqb[12], auth[256], plain[256], frame[768];
	uint8_t wrapper[KS_KDP_WRAPPER_LEN];
	const uint8_t *v;
	struct ks_rrb_message msg;
	struct ks_rrb_plain dec;
	struct ks_kdp_element assoc, response, response_b;
	struct ks_state base, s;
	uint32_t corr;
	uint16_t oid;
	unsigned int rrb_count, ioctl_count;
	int ioctl_bss;
	size_t alen, plen, flen, i, n, pending;

	for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t) (i + 1);
	for (i = 0; i < sizeof(nonce); i++) {
		nonce[i] = (uint8_t) (i + 0x10); nonce2[i] = (uint8_t) (i + 0x30);
		n0[i] = (uint8_t) (i + 0x50); n0b[i] = (uint8_t) (i + 0x70);
		n1[i] = (uint8_t) (i + 0x90);
	}
	for (i = 0; i < sizeof(pmk); i++) pmk[i] = (uint8_t) (i + 0xa0);
	CHECK(inet_pton(AF_INET, "192.0.2.22", &corr) == 1);
	memset(&base, 0, sizeof(base)); ks_config_defaults(&base.cfg);
	base.cfg.ft_enabled = true; base.rrb_key_loaded = true;
	memcpy(base.rrb_key, key, sizeof(key)); memcpy(base.transport_mac, local, 6);
	base.packet_fd = base.ioctl_fd = -2; base.transport_ifindex = 1;
	base.cfg.n_bss = 2; base.cfg.bss[0].active = base.cfg.bss[0].mtk_kdp = true;
	base.cfg.bss[0].ifindex = 9; memcpy(base.cfg.bss[0].bssid, local_bss, 6);
	memcpy(base.cfg.bss[0].r1kh_id, local_bss, 6);
	memcpy(base.cfg.bss[0].r0kh_id, r0, sizeof(r0) - 1);
	base.cfg.bss[0].r0kh_id_len = sizeof(r0) - 1;
	base.cfg.bss[1].active = base.cfg.bss[1].mtk_kdp = true;
	base.cfg.bss[1].ifindex = 10;
	memcpy(base.cfg.bss[1].bssid, (uint8_t[]) { 0x02, 2, 2, 2, 2, 4 }, 6);
	memcpy(base.cfg.bss[1].r0kh_id, other_r0, sizeof(other_r0) - 1);
	base.cfg.bss[1].r0kh_id_len = sizeof(other_r0) - 1;
	base.cfg.n_ft_peers = 1; base.cfg.ft_peers[0].used = true;
	base.cfg.ft_peers[0].sink_ready = true;
	base.cfg.ft_peers[0].peer_ip.s_addr = corr;
	memcpy(base.cfg.ft_peers[0].transport, remote, 6);
	memcpy(base.cfg.ft_peers[0].bssid, remote, 6);
	memcpy(base.cfg.ft_peers[0].r1kh_id, r1, 6);
	base.cfg.ft_peers[0].rx_domain = 0x12345679;
	base.cfg.ft_peers[0].rx_count = 1; base.cfg.ft_peers[0].rx_last[0] = 19;
	base.cfg.ft_peers[0].tx_domain = 0x87654321;
	base.cfg.ft_peers[0].tx_seq = 7;
	ks_put_le32(seq, base.cfg.ft_peers[0].rx_domain); ks_put_le32(seq + 4, 20);
	ks_put_le32(seq + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));

	s = base; ks_mtk_test_reset();
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(!rrb_count && ioctl_count == 1);
	CHECK(!ks_mtk_test_last_ioctl(&oid, &ioctl_bss, wrapper, sizeof(wrapper), &n));
	CHECK(oid == KS_OID_FT_QUERY && ioctl_bss == 0 && n == sizeof(wrapper));
	CHECK(!memcmp(wrapper, &corr, 4) &&
	      !memcmp(wrapper + 12 + 0x07, sta, 6) &&
	      wrapper[12 + 0x40] == sizeof(r0) - 1 &&
	      !memcmp(wrapper + 12 + 0x10, r0, sizeof(r0) - 1) &&
	      !memcmp(wrapper + 12 + 0x41, n0, 16) &&
	      !memcmp(wrapper + 12 + 0x51, r1, 6) &&
	      !memcmp(wrapper + 12 + 0x57, sta, 6));
	for (pending = 0; pending < KS_MAX_KDP_PENDING; pending++)
		if (s.kdp_pending[pending].used) break;
	CHECK(pending < KS_MAX_KDP_PENDING && s.kdp_pending[pending].rrb_pull &&
	      !memcmp(s.kdp_pending[pending].nonce, nonce, 16) &&
	      !memcmp(s.kdp_pending[pending].pmkr0name, n0, 16));
	ks_put_le32(seq + 4, 21);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 1);
	memset(&assoc, 0, sizeof(assoc));
	memcpy(assoc.raw, "\xff\xff\x00\xa3\x00\x0e\x2e", 7);
	memcpy(assoc.raw + 0x07, sta, 6); memcpy(assoc.raw + 0x57, sta, 6);
	CHECK(ks_kdp_prewarm_event(&s, 0, &assoc) == 0 && s.kdp_pending[pending].rrb_pull);
	ks_put_le32(seq + 4, 20);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	ks_put_le32(seq + 4, 22);
	CHECK(!pull_frame(key, remote, local, nonce2, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0b, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(rrb_count == 1 && ioctl_count == 1 && s.kdp_pending[pending].used &&
	      !memcmp(s.kdp_pending[pending].nonce, nonce, 16));
	CHECK(!ks_kdp_from_rrb(&response, sta, (const uint8_t *) r0, sizeof(r0) - 1,
			       n0, r1, n1, pmk, local_bss, 0x10, 120));
	CHECK(!ks_kdp_handle_response(&s, 9, corr ^ 1, &response) &&
	      s.kdp_pending[pending].used);
	response.raw[0x41] ^= 1;
	CHECK(!ks_kdp_handle_response(&s, 9, corr, &response) &&
	      s.kdp_pending[pending].used);
	response.raw[0x41] ^= 1;
	CHECK(!ks_kdp_handle_response(&s, 9, corr, &response));
	CHECK(!s.kdp_pending[pending].used);
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(rrb_count == 2 && ioctl_count == 1);
	CHECK(!ks_mtk_test_last_rrb(frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg) && msg.subtype == 2 &&
	      !memcmp(msg.src, local, 6) && !memcmp(msg.dst, remote, 6));
	CHECK(get_tlv(msg.auth, msg.auth_len, 2, &v, &n) == 1 && n == 16 &&
	      !memcmp(v, nonce, 16));
	CHECK(get_tlv(msg.auth, msg.auth_len, 1, &v, &n) == 1 && n == 12 &&
	      ks_get_le32(v) == base.cfg.ft_peers[0].tx_domain && ks_get_le32(v + 4) == 8);
	CHECK(get_tlv(msg.auth, msg.auth_len, 4, &v, &n) == 1 && n == sizeof(r0) - 1 &&
	      !memcmp(v, r0, n));
	CHECK(get_tlv(msg.auth, msg.auth_len, 5, &v, &n) == 1 && n == 6 && !memcmp(v, r1, 6));
	CHECK(!ks_rrb_decrypt(key, &msg, &dec));
	CHECK(get_tlv(dec.data, dec.len, 6, &v, &n) == 1 && n == 6 && !memcmp(v, sta, 6));
	CHECK(get_tlv(dec.data, dec.len, 7, &v, &n) == 0);
	CHECK(get_tlv(dec.data, dec.len, 10, &v, &n) == 1 && n == 32 && !memcmp(v, pmk, 32));
	CHECK(get_tlv(dec.data, dec.len, 9, &v, &n) == 1 && n == 16 && !memcmp(v, n1, 16));
	CHECK(get_tlv(dec.data, dec.len, 11, &v, &n) == 1 && n == 2 && ks_get_le16(v) == 0x10);
	CHECK(get_tlv(dec.data, dec.len, 12, &v, &n) == 1 && n == 2 && ks_get_le16(v) == 120);

	s = base; s.cfg.ft_peers[0].rx_count = 0; ks_mtk_test_reset();
	ks_put_le32(seq + 4, 20);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(&rrb_count, &ioctl_count); CHECK(rrb_count == 1 && !ioctl_count);
	for (pending = 0; pending < KS_MAX_RRB_PENDING; pending++)
		if (s.rrb_pending[pending].used) break;
	CHECK(pending < KS_MAX_RRB_PENDING && s.rrb_pending[pending].subtype == 1);
	alen = 0; ks_put_le32(seqb, base.cfg.ft_peers[0].rx_domain);
	ks_put_le32(seqb + 4, 21); ks_put_le32(seqb + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, s.rrb_pending[pending].nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seqb, 12));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, r0, sizeof(r0) - 1));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!ks_rrb_build(5, remote, local, key, auth, alen, NULL, 0,
			    frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 1);

	s = base; s.ioctl_fd = -1; ks_mtk_test_reset();
	ks_put_le32(seq + 4, 20);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(&rrb_count, &ioctl_count); CHECK(rrb_count == 1 && !ioctl_count);
	CHECK(!ks_mtk_test_last_rrb(frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg) && msg.subtype == 2);
	CHECK(get_tlv(msg.auth, msg.auth_len, 2, &v, &n) == 1 && n == 16 &&
	      !memcmp(v, nonce, 16));
	CHECK(!ks_rrb_decrypt(key, &msg, &dec));
	CHECK(get_tlv(dec.data, dec.len, 6, &v, &n) == 1 && n == 6 && !memcmp(v, sta, 6));
	CHECK(get_tlv(dec.data, dec.len, 10, &v, &n) == 0 &&
	      get_tlv(dec.data, dec.len, 9, &v, &n) == 0 &&
	      get_tlv(dec.data, dec.len, 11, &v, &n) == 0 &&
	      get_tlv(dec.data, dec.len, 12, &v, &n) == 0);

	s = base; ks_mtk_test_reset();
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	for (pending = 0; pending < KS_MAX_KDP_PENDING; pending++)
		if (s.kdp_pending[pending].used) break;
	CHECK(pending < KS_MAX_KDP_PENDING);
	s.kdp_pending[pending].deadline_ms = ks_now_ms();
	ks_kdp_expire(&s, ks_now_ms());
	ks_mtk_test_counts(&rrb_count, &ioctl_count);
	CHECK(rrb_count == 1 && ioctl_count == 1 && !s.kdp_pending[pending].used);

	s = base; ks_mtk_test_reset();
	CHECK(!pull_frame(key, remote2, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) "unknown", 7,
			  r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1b, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	frame[flen - 1] ^= 1; CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, (uint8_t[16]) {0}, sta, frame, &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	ks_put_le32(seq + 4, 21);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, bad_sta, frame, &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	alen = plen = 0; ks_put_le32(seq + 4, 22);
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, 12));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, r0, sizeof(r0) - 1));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 7, n0, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 7, n0, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!ks_rrb_build(1, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	alen = plen = 0; ks_put_le32(seq + 4, 23);
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, nonce, 16));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, 12));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, r0, sizeof(r0) - 1));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 7, n0, 15));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!ks_rrb_build(1, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	alen = plen = 0; ks_put_le32(seq + 4, 24);
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 2, nonce, 15));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 1, seq, 12));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 4, r0, sizeof(r0) - 1));
	CHECK(!put_tlv(auth, sizeof(auth), &alen, 5, r1, 6));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 7, n0, 16));
	CHECK(!put_tlv(plain, sizeof(plain), &plen, 6, sta, 6));
	CHECK(!ks_rrb_build(1, remote, local, key, auth, alen, plain, plen,
			    frame, sizeof(frame), &flen));
	CHECK(ks_rrb_handle_frame(&s, frame, flen) < 0);
	ks_mtk_test_counts(&rrb_count, &ioctl_count); CHECK(!rrb_count && !ioctl_count);

	s = base; s.cfg.n_ft_peers = 2; s.cfg.ft_peers[1] = s.cfg.ft_peers[0];
	memcpy(s.cfg.ft_peers[1].transport, remote2, 6);
	memcpy(s.cfg.ft_peers[1].bssid, remote2, 6);
	memcpy(s.cfg.ft_peers[1].r1kh_id, r1b, 6);
	s.cfg.ft_peers[1].rx_domain = 0x1234567b;
	s.cfg.ft_peers[1].tx_domain = 0x87654323;
	ks_mtk_test_reset(); ks_put_le32(seq + 4, 20);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_put_le32(seqb, s.cfg.ft_peers[1].rx_domain); ks_put_le32(seqb + 4, 20);
	ks_put_le32(seqb + 8, (uint32_t) (ks_now_ms() / 1000));
	CHECK(!pull_frame(key, remote2, local, nonce2, seqb, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1b, n0b, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(NULL, &ioctl_count); CHECK(ioctl_count == 2);
	CHECK(!ks_kdp_from_rrb(&response_b, sta, (const uint8_t *) r0, sizeof(r0) - 1,
			       n0b, r1b, n1, pmk, local_bss, 0x10, 120));
	CHECK(!ks_kdp_handle_response(&s, 9, corr, &response_b));
	CHECK(!ks_mtk_test_last_rrb(frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg) && !memcmp(msg.dst, remote2, 6));
	CHECK(!ks_kdp_handle_response(&s, 9, corr, &response));
	CHECK(!ks_mtk_test_last_rrb(frame, sizeof(frame), &flen));
	CHECK(!ks_rrb_parse_frame(frame, flen, &msg) && !memcmp(msg.dst, remote, 6));
	for (i = n = 0; i < KS_MAX_KDP_PENDING; i++) n += s.kdp_pending[i].used;
	CHECK(!n);

	s = base; ks_mtk_test_reset();
	for (i = 0; i < KS_MAX_KDP_PENDING; i++) {
		s.kdp_pending[i].used = true; s.kdp_pending[i].source_bss = 1;
	}
	ks_put_le32(seq + 4, 20);
	CHECK(!pull_frame(key, remote, local, nonce, seq, (const uint8_t *) r0,
			  sizeof(r0) - 1, r1, n0, sta, frame, &flen));
	CHECK(!ks_rrb_handle_frame(&s, frame, flen));
	ks_mtk_test_counts(&rrb_count, &ioctl_count); CHECK(rrb_count == 1 && !ioctl_count);
	for (i = n = 0; i < KS_MAX_KDP_PENDING; i++) n += s.kdp_pending[i].used;
	CHECK(n == KS_MAX_KDP_PENDING);
	ks_secure_clear(pmk, sizeof(pmk));
	return 0;
}

static int test_rrb_dedupe(void)
{
	struct ks_state s;
	struct ks_kdp_element event;
	uint8_t sta[6] = { 0x02, 1, 2, 3, 4, 5 };
	uint8_t r1a[6] = { 0x02, 6, 7, 8, 9, 10 };
	uint8_t r1b[6] = { 0x02, 6, 7, 8, 9, 11 };
	uint8_t n0[16], nonce[16];
	unsigned int rrb, ioctl_count;
	size_t i;

	for (i = 0; i < sizeof(n0); i++) n0[i] = (uint8_t) (i + 1);
	memset(&s, 0, sizeof(s)); ks_config_defaults(&s.cfg);
	s.packet_fd = -2; s.transport_ifindex = 1;
	s.cfg.n_bss = 2;
	for (i = 0; i < s.cfg.n_bss; i++)
		s.cfg.bss[i].active = s.cfg.bss[i].mtk_kdp = true;
	memcpy(s.cfg.bss[0].r1kh_id, r1a, 6);
	memcpy(s.cfg.bss[1].r1kh_id, r1b, 6);
	s.cfg.n_ft_peers = 1; s.cfg.ft_peers[0].used = true;
	memcpy(s.cfg.ft_peers[0].transport,
	       (uint8_t[]) { 0x02, 10, 11, 12, 13, 14 }, 6);
	memcpy(s.cfg.ft_peers[0].r0kh_id, "remote", 6);
	s.cfg.ft_peers[0].r0kh_id_len = 6;
	kdp_request(&event, sta, NULL, 0, n0, r1a);
	ks_mtk_test_reset();
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	memcpy(nonce, s.pull_pending[0].nonce, sizeof(nonce));
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	ks_mtk_test_counts(&rrb, &ioctl_count);
	CHECK(rrb == 1 && ioctl_count == 0 &&
	      !memcmp(nonce, s.pull_pending[0].nonce, sizeof(nonce)));
	event.raw[0x41] ^= 1;
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	ks_mtk_test_counts(&rrb, NULL); CHECK(rrb == 2);
	event.raw[0x41] ^= 1;
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	ks_mtk_test_counts(&rrb, NULL); CHECK(rrb == 3);
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) break;
	CHECK(i < KS_MAX_RRB_PENDING);
	s.pull_pending[i].deadline_ms = ks_now_ms();
	CHECK(!ks_rrb_send_pull(&s, 0, &event));
	ks_mtk_test_counts(&rrb, NULL); CHECK(rrb == 4);
	memcpy(event.raw + 0x51, r1b, 6);
	CHECK(!ks_rrb_send_pull(&s, 1, &event));
	ks_mtk_test_counts(&rrb, NULL); CHECK(rrb == 5);
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s.pull_pending[i].used) CHECK(s.pull_pending[i].target_bss == 1);
	return 0;
}

static const char table_header_fmt[] =
	"\n%-13s%-3s%-4s%-3s%-2s%-5s%-5s%-11s%-21s%-21s%-6s%-5s%-5s%-5s%-4s"
	"%-3s%-3s%-3s%-2s%-2s%-2s%-3s%-3s%-2s%-3s\n";

static size_t table_header(char *out, size_t cap)
{
	int n = snprintf(out, cap, table_header_fmt, "MAC", "AP", "AID", "PS", "A", "CTxR",
			 "LRxR", "LDT", "RxB", "TxB", "HT", "Mode", "ShGI", "RSSI", "MCS", "SS",
			 "BF", "MU", "K", "R", "V", "RP", "RM", "W", "AU");
	return n < 0 ? 0 : (size_t) n;
}

static size_t table_row(char *out, size_t cap, const uint8_t mac[6], int ap, int rssi)
{
	int n = snprintf(out, cap, "%02x%02x%02x%02x%02x%02x %-3d%-4d%-3d%-2d%-5d%-5d%-11u"
			 "%-21llu%-21llu%-6s%-5s%-5d%-5d%-4d%-3d%-3d%-3d%-2d%-2d%-2d%-3d%-3d%-2d%-3d\n",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ap, 1, 0, 1, 3, 4, 0u,
			 1234567890ull, 9876543210ull, "HT", "11n", 1, rssi, 7, 2, 0, 0, 1, 0, 1, 0,
			 0, 1, 0);
	return n < 0 ? 0 : (size_t) n;
}

static int test_reconcile(void)
{
	struct ks_state s;
	struct ks_station *st;
	static char t0[40000], t1[4096];
	uint8_t a[6] = { 0x02, 1, 2, 3, 4, 5 }, b[6] = { 0x02, 6, 7, 8, 9, 10 };
	uint8_t c[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, x[6] = { 0x02, 0, 0, 0, 0, 1 };
	uint8_t y[6] = { 0x02, 0, 0, 0, 0, 2 };
	uint64_t now = 5000000;
	size_t n, i;

	sample_state(&s, 2); s.stations[0].connected_ms = now - 100;
	strcpy(s.cfg.bss[0].ifname, "ra0"); strcpy(s.cfg.bss[1].ifname, "ra8");
	s.ioctl_fd = 1; mock_wext = true;
	strcpy(mock_table[0].ifname, "ra0"); strcpy(mock_table[1].ifname, "ra8");
	mock_table[0].text = t0; mock_table[1].text = t1;
	mock_table[0].error = mock_table[1].error = false; mock_table_len = 0;
	CHECK(table_header(t1, sizeof(t1)) == 141 && table_row(t0, sizeof(t0), a, 0, -45) == 140);

	/* single BSS with a missed association, empty second BSS */
	n = table_header(t0, sizeof(t0));
	n += table_row(t0 + n, sizeof(t0) - n, c, 0, -45);
	table_row(t0 + n, sizeof(t0) - n, a, 0, -45);
	table_header(t1, sizeof(t1));
	mock_table_calls = 0;
	CHECK(!ks_backend_reconcile(&s, now) && mock_table_calls == 2 && !s.reconcile_off);
	CHECK(s.next_reconcile_ms == now + 60000);
	st = ks_station_get(&s, a, false);
	CHECK(st && st->connected && st->bss_index == 0 && st->connected_ms == now &&
	      st->seen_2ghz && !st->seen_5ghz && st->signal[0] == -45 && st->seen_ms[0] == now);
	CHECK(s.stations[0].connected && s.stations[0].connected_ms == now - 100);
	CHECK(ks_backend_reconcile(&s, now + 59999) < 0 && mock_table_calls == 2);
	CHECK(!ks_backend_reconcile(&s, now + 60000) && mock_table_calls == 4);
	CHECK(st->connected && st->connected_ms == now &&
	      s.stations[0].connected_ms == now - 100 && s.stations[0].bss_index == 0);

	/* second BSS: c moved to ra8, b missed there, a unchanged */
	now += 120000;
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, a, 0, -45);
	n = table_header(t1, sizeof(t1));
	n += table_row(t1 + n, sizeof(t1) - n, c, 8, -45);
	table_row(t1 + n, sizeof(t1) - n, b, 8, -45);
	CHECK(!ks_backend_reconcile(&s, now));
	CHECK(s.stations[0].connected && s.stations[0].bss_index == 1 &&
	      s.stations[0].connected_ms == now && s.stations[0].seen_2ghz &&
	      s.stations[0].seen_5ghz && s.stations[0].seen_ms[0] &&
	      s.stations[0].signal[1] == -45 && s.stations[0].seen_ms[1] == now);
	st = ks_station_get(&s, b, false);
	CHECK(st && st->connected && st->bss_index == 1 && st->seen_5ghz);
	st = ks_station_get(&s, a, false);
	CHECK(st && st->connected && st->bss_index == 0 && st->connected_ms == now - 120000);

	/* missed disconnect */
	now += 60000;
	table_header(t0, sizeof(t0));
	CHECK(!ks_backend_reconcile(&s, now));
	CHECK(st->used && !st->connected && st->connected_ms == now && st->bss_index == 0);
	CHECK(s.stations[0].connected && ks_station_get(&s, b, false)->connected);

	/* one failed query leaves everything untouched */
	now += 60000;
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	table_header(t1, sizeof(t1));
	mock_table[1].error = true; mock_table_calls = 0;
	CHECK(ks_backend_reconcile(&s, now) < 0 && mock_table_calls == 2 && !s.reconcile_off);
	CHECK(!ks_station_get(&s, x, false) && s.stations[0].connected &&
	      ks_station_get(&s, b, false)->connected && !st->connected);
	mock_table[1].error = false;

	/* malformed rows, inconsistent indices and truncation are rejected */
	now += 60000;
	n = table_header(t1, sizeof(t1)); table_row(t1 + n, sizeof(t1) - n, c, 8, -45);
	n = table_header(t0, sizeof(t0));
	n += table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	table_row(t0 + n, sizeof(t0) - n, a, 1, -45);
	CHECK(ks_backend_reconcile(&s, now) < 0 && !ks_station_get(&s, x, false));
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, x, 8, -45);
	CHECK(ks_backend_reconcile(&s, now) < 0 && !ks_station_get(&s, x, false));
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, c, 0, -45);
	CHECK(ks_backend_reconcile(&s, now) < 0 && s.stations[0].bss_index == 1);
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0));
	n += table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	CHECK(ks_backend_reconcile(&s, now) < 0 && !ks_station_get(&s, x, false));
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0));
	snprintf(t0 + n, sizeof(t0) - n, "0200000000zz 0  1\n");
	CHECK(ks_backend_reconcile(&s, now) < 0 && !ks_station_get(&s, x, false));
	s.next_reconcile_ms = 0;
	snprintf(t0 + n, sizeof(t0) - n, "010000000001 0  1\n");
	CHECK(ks_backend_reconcile(&s, now) < 0);
	s.next_reconcile_ms = 0;
	snprintf(t0 + n, sizeof(t0) - n, "02000000001 0  1\n");
	CHECK(ks_backend_reconcile(&s, now) < 0);
	s.next_reconcile_ms = 0;
	snprintf(t0 + n, sizeof(t0) - n, "020000000001\n");
	CHECK(ks_backend_reconcile(&s, now) < 0);
	s.next_reconcile_ms = 0;
	snprintf(t0 + n, sizeof(t0) - n, "020000000001 x  1\n");
	CHECK(ks_backend_reconcile(&s, now) < 0);
	s.next_reconcile_ms = 0;
	table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	mock_table_len = UINT16_MAX - 139;
	CHECK(ks_backend_reconcile(&s, now) < 0 && !ks_station_get(&s, x, false) &&
	      !s.reconcile_off);
	mock_table_len = 0; s.next_reconcile_ms = 0;
	CHECK(!ks_backend_reconcile(&s, now) && ks_station_get(&s, x, false)->connected);

	/* RSSI column is optional and only plausible values are used */
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0)); memcpy(strstr(t0, "RSSI"), "RSS ", 4);
	n += table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	table_row(t0 + n, sizeof(t0) - n, y, 0, -50);
	CHECK(!ks_backend_reconcile(&s, now));
	st = ks_station_get(&s, y, false);
	CHECK(st && st->connected && !st->signal[0] && !st->seen_ms[0]);
	s.next_reconcile_ms = 0;
	n = table_header(t0, sizeof(t0));
	n += table_row(t0 + n, sizeof(t0) - n, x, 0, -45);
	table_row(t0 + n, sizeof(t0) - n, y, 0, 5);
	CHECK(!ks_backend_reconcile(&s, now) && st->connected && !st->seen_ms[0]);
	s.next_reconcile_ms = 0;
	table_row(t0 + n, sizeof(t0) - n, y, 0, -71);
	CHECK(!ks_backend_reconcile(&s, now) && st->signal[0] == -71 && st->seen_ms[0] == now);


	/* station table bounds */
	n = table_header(t0, sizeof(t0));
	for (i = 0; i <= KS_MAX_STA; i++) {
		uint8_t m[6] = { 0x02, 0x33, 0, 0, (uint8_t) (i >> 8), (uint8_t) i };
		n += table_row(t0 + n, sizeof(t0) - n, m, 0, -45);
	}
	CHECK(n < sizeof(t0)); s.next_reconcile_ms = 0;
	CHECK(ks_backend_reconcile(&s, now) < 0 && ks_station_get(&s, x, false)->connected);
	for (i = 0; i < KS_MAX_STA; i++) {
		s.stations[i].used = true;
		memcpy(s.stations[i].addr, (uint8_t[]) { 0x02, 0x44, 0, 0, (uint8_t) (i >> 8), (uint8_t) i }, 6);
		s.stations[i].connected = false;
	}
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, a, 0, -45);
	table_header(t1, sizeof(t1));
	s.next_reconcile_ms = 0;
	CHECK(!ks_backend_reconcile(&s, now) && !ks_station_get(&s, a, false));
	for (i = 0; i < KS_MAX_STA; i++) CHECK(!s.stations[i].connected);

	/* unsupported or unknown format disables reconciliation only */
	sample_state(&s, 2); s.cfg.ft_enabled = true; s.cfg.bss[0].mtk_kdp = true;
	strcpy(s.cfg.bss[0].ifname, "ra0"); strcpy(s.cfg.bss[1].ifname, "ra8"); s.ioctl_fd = 1;
	n = table_header(t0, sizeof(t0));
	table_row(t0 + n, sizeof(t0) - n, a, 0, -45);
	mock_priv_missing = true; mock_table_calls = 0;
	CHECK(ks_backend_reconcile(&s, now) < 0 && s.reconcile_off && !mock_table_calls);
	CHECK(s.cfg.usteer_enabled && s.cfg.ft_enabled && s.cfg.bss[0].mtk_kdp &&
	      s.stations[0].connected && !ks_station_get(&s, a, false));
	s.next_reconcile_ms = 0;
	CHECK(ks_backend_reconcile(&s, now) < 0 && !mock_table_calls);
	memcpy(mock_load, (uint8_t[]) { 0, 1, 1, 5, 0, 1, 23, 0 }, 8);
	mock_load_len = 8; mock_load_error = false; s.next_load_ms = 0; s.cfg.bss[1].active = false;
	ks_backend_update_load(&s); CHECK(s.cfg.bss[0].load == 23);
	s.cfg.bss[1].active = true;
	mock_priv_missing = false; s.reconcile_off = false; s.next_reconcile_ms = 0;
	mock_priv_error = true;
	CHECK(ks_backend_reconcile(&s, now) < 0 && !s.reconcile_off && !mock_table_calls);
	mock_priv_error = false; s.next_reconcile_ms = 0;
	snprintf(t0, sizeof(t0), "\nAddr AID\n020102030405 0 1\n");
	CHECK(ks_backend_reconcile(&s, now) < 0 && s.reconcile_off && mock_table_calls == 1);
	CHECK(!ks_station_get(&s, a, false) && s.stations[0].connected);
	s.reconcile_off = false; s.next_reconcile_ms = 0; mock_table_calls = 0;
	s.cfg.usteer_enabled = false;
	CHECK(ks_backend_reconcile(&s, now) < 0 && !mock_table_calls);
	mock_wext = false;
	return 0;
}

static int test_backend(void)
{
	struct ks_state s;

	memset(&s, 0, sizeof(s)); ks_config_defaults(&s.cfg);
	strcpy(s.cfg.transport_if, "lo"); s.cfg.ft_enabled = s.rrb_key_loaded = true;
	memset(s.rrb_key, 1, sizeof(s.rrb_key));
	if (ks_backend_open(&s)) {
		CHECK(!s.cfg.ft_enabled && !s.cfg.usteer_enabled);
	} else {
		CHECK(s.cfg.ft_enabled || s.cfg.usteer_enabled);
		CHECK(s.cfg.ft_enabled == (s.packet_fd >= 0));
		CHECK(s.cfg.usteer_enabled == (s.udp_fd >= 0 && s.netlink_fd >= 0));
	}
	CHECK(s.cfg.ft_enabled || (!s.rrb_key_loaded && !s.rrb_key[0]));
	ks_backend_close(&s);
	CHECK(s.packet_fd < 0 && s.udp_fd < 0 && s.netlink_fd < 0 && s.ioctl_fd < 0);
	return 0;
}

int main(void)
{
	int n = 0;

	if (test_usteer()) return 1;
	n++;
	if (test_aes_siv()) return 1;
	n++;
	if (test_key_expansion()) return 1;
	n++;
	if (test_config()) return 1;
	n++;
	if (test_kdp()) return 1;
	n++;
	if (test_association()) return 1;
	n++;
	if (test_rrb()) return 1;
	n++;
	if (test_rrb_pull_resp()) return 1;
	n++;
	if (test_rrb_incoming_pull()) return 1;
	n++;
	if (test_rrb_dedupe()) return 1;
	n++;
	if (test_reconcile()) return 1;
	n++;
	if (test_backend()) return 1;
	n++;
	printf("ok %d groups\n", n);
	return 0;
}
