#define _GNU_SOURCE
#include "keensteer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
	APMSG_ID, APMSG_SEQ, APMSG_NODES, APMSG_HOST_INFO
};
enum {
	NODE_NAME, NODE_FREQ, NODE_N_ASSOC, NODE_STATIONS, NODE_NOISE,
	NODE_LOAD, NODE_SSID, NODE_MAX_ASSOC, NODE_RRM_NR, NODE_INFO,
	NODE_BSSID, NODE_CHANNEL, NODE_OP_CLASS
};
enum {
	STA_ADDR, STA_SIGNAL, STA_TIMEOUT, STA_SEEN, STA_CONNECTED,
	STA_CLASSIC_LAST_CONNECTED,
	STA_NG_SEEN_5GHZ,
	STA_NG_LAST_CONNECTED
};

#define BLOB_EXTENDED 0x80000000u
#define BLOB_ID_SHIFT 24
#define BLOB_LEN_MASK 0x00ffffffu
#define BLOBMSG_ARRAY 1
#define BLOBMSG_STRING 3

struct bb {
	uint8_t *p;
	size_t cap;
	size_t len;
	size_t stack[16];
	unsigned int depth;
};

static size_t pad4(size_t n) { return (n + 3u) & ~3u; }

static int reserve(struct bb *b, size_t n)
{
	return n <= b->cap - b->len ? 0 : -1;
}

static int attr(struct bb *b, unsigned int id, const void *data, size_t len)
{
	size_t raw = 4 + len, padded = pad4(raw);
	if (id > 127 || raw > BLOB_LEN_MASK || reserve(b, padded)) return -1;
	ks_put_be32(b->p + b->len, ((uint32_t) id << BLOB_ID_SHIFT) | (uint32_t) raw);
	if (len) memcpy(b->p + b->len + 4, data, len);
	memset(b->p + b->len + raw, 0, padded - raw);
	b->len += padded;
	return 0;
}

static int ai32(struct bb *b, unsigned int id, int32_t val)
{
	uint8_t v[4]; ks_put_be32(v, (uint32_t) val); return attr(b, id, v, sizeof(v));
}

static int ai8(struct bb *b, unsigned int id, uint8_t val)
{
	return attr(b, id, &val, sizeof(val));
}

static int astr(struct bb *b, unsigned int id, const char *s)
{
	return attr(b, id, s, strlen(s) + 1);
}

static int nest_start(struct bb *b, unsigned int id)
{
	if (b->depth >= sizeof(b->stack) / sizeof(b->stack[0]) || reserve(b, 4)) return -1;
	b->stack[b->depth++] = b->len;
	ks_put_be32(b->p + b->len, (uint32_t) id << BLOB_ID_SHIFT);
	b->len += 4;
	return 0;
}

static int nest_end(struct bb *b)
{
	size_t start, raw, padded;
	uint32_t h;
	if (!b->depth) return -1;
	start = b->stack[--b->depth]; raw = b->len - start; padded = pad4(raw);
	if (raw > BLOB_LEN_MASK || reserve(b, padded - raw)) return -1;
	h = ks_get_be32(b->p + start) & ~BLOB_LEN_MASK;
	ks_put_be32(b->p + start, h | (uint32_t) raw);
	memset(b->p + b->len, 0, padded - raw); b->len += padded - raw;
	return 0;
}

static int blobmsg(struct bb *b, unsigned int type, const void *payload, size_t len)
{
	uint8_t hdr[8];
	size_t body = 4 + len, raw = 4 + body, padded = pad4(raw);
	if (raw > BLOB_LEN_MASK || reserve(b, padded)) return -1;
	ks_put_be32(hdr, BLOB_EXTENDED | ((uint32_t) type << BLOB_ID_SHIFT) | (uint32_t) raw);
	hdr[4] = hdr[5] = hdr[6] = hdr[7] = 0; /* be16 namelen=0, NUL, pad */
	memcpy(b->p + b->len, hdr, sizeof(hdr));
	if (len) memcpy(b->p + b->len + 8, payload, len);
	memset(b->p + b->len + raw, 0, padded - raw); b->len += padded;
	return 0;
}

static int blobmsg_string_to(uint8_t *out, size_t cap, const char *s, size_t *used)
{
	struct bb b = { .p = out, .cap = cap };
	if (blobmsg(&b, BLOBMSG_STRING, s, strlen(s) + 1)) return -1;
	*used = b.len; return 0;
}

static int add_neighbor_report(struct bb *b, const struct ks_bss *n)
{
	uint8_t nested[256];
	char nr[64];
	size_t nlen;
	unsigned int phy = n->band == KS_BAND_2GHZ ? 7 : 9;

	snprintf(nr, sizeof(nr),
		 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		 n->bssid[0], n->bssid[1], n->bssid[2], n->bssid[3], n->bssid[4], n->bssid[5],
		 0x00, 0x00, 0x00, 0x00, n->op_class & 0xff, n->channel & 0xff, phy);
	if (blobmsg_string_to(nested, sizeof(nested), nr, &nlen)) return -1;
	if (nest_start(b, NODE_RRM_NR)) return -1;
	if (blobmsg(b, BLOBMSG_ARRAY, nested, nlen)) return -1;
	return nest_end(b);
}

static int add_station(struct bb *b, const struct ks_state *s,
		       const struct ks_station *st, int bss_index, uint64_t now)
{
	uint64_t age64, seen_ms;
	uint64_t conn64;
	bool connected;
	if (bss_index < 0 || bss_index >= KS_MAX_BSS || !st->seen_ms[bss_index]) return 0;
	seen_ms = st->seen_ms[bss_index]; age64 = now >= seen_ms ? now - seen_ms : 0;
	connected = st->connected && st->bss_index == bss_index;
	conn64 = connected ? 0 : (st->connected_ms && now >= st->connected_ms ?
				  now - st->connected_ms : age64);
	int32_t age = age64 > INT32_MAX ? INT32_MAX : (int32_t) age64;
	int32_t last = conn64 > INT32_MAX ? INT32_MAX : (int32_t) conn64;
	int32_t timeout = (int32_t) s->cfg.station_ttl_ms - age;

	if (timeout <= 0 || nest_start(b, 0)) return timeout <= 0 ? 0 : -1;
	if (attr(b, STA_ADDR, st->addr, 6) || ai32(b, STA_SIGNAL, st->signal[bss_index]) ||
	    ai32(b, STA_TIMEOUT, timeout) || ai32(b, STA_SEEN, age) ||
	    ai8(b, STA_CONNECTED, connected) ||
	    /* ID 5/i32 is classic last_connected. NG ignores this type. */
	    ai32(b, STA_CLASSIC_LAST_CONNECTED, last) ||
	    /* ID 5/i8 is NG seen_2ghz. Classic ignores this type. */
	    ai8(b, STA_CLASSIC_LAST_CONNECTED, st->seen_2ghz) ||
	    ai8(b, STA_NG_SEEN_5GHZ, st->seen_5ghz) ||
	    ai32(b, STA_NG_LAST_CONNECTED, last) || nest_end(b)) return -1;
	return 0;
}

int ks_usteer_encode(const struct ks_state *s, uint8_t *out, size_t cap, size_t *out_len)
{
	struct bb b = { .p = out, .cap = cap };
	uint64_t now = ks_now_ms();
	size_t i, j;

	if (!out || !out_len || cap < 16 || nest_start(&b, 0)) return -1;
	if (ai32(&b, APMSG_ID, (int32_t) s->usteer_id) ||
	    ai32(&b, APMSG_SEQ, (int32_t) (s->usteer_seq + 1)) ||
	    nest_start(&b, APMSG_NODES)) return -1;
	for (i = 0; i < s->cfg.n_bss; i++) {
		const struct ks_bss *n = &s->cfg.bss[i];
		int assoc = 0;
		if (!n->active) continue;
		for (j = 0; j < KS_MAX_STA; j++)
			if (s->stations[j].used && s->stations[j].connected && s->stations[j].bss_index == (int) i) assoc++;
		if (nest_start(&b, 0) || astr(&b, NODE_NAME, n->name) ||
		    ai32(&b, NODE_FREQ, n->freq) || ai32(&b, NODE_N_ASSOC, assoc) ||
		    ai32(&b, NODE_NOISE, n->noise) || ai32(&b, NODE_LOAD, n->load) ||
		    astr(&b, NODE_SSID, n->ssid) || ai32(&b, NODE_MAX_ASSOC, n->max_assoc) ||
		    attr(&b, NODE_BSSID, n->bssid, 6) || ai32(&b, NODE_CHANNEL, n->channel) ||
		    ai32(&b, NODE_OP_CLASS, n->op_class) || add_neighbor_report(&b, n) ||
		    nest_start(&b, NODE_STATIONS)) return -1;
		for (j = 0; j < KS_MAX_STA; j++)
			if (s->stations[j].used && add_station(&b, s, &s->stations[j], (int) i, now)) return -1;
		if (nest_end(&b) || nest_end(&b)) return -1;
	}
	if (nest_end(&b) || nest_end(&b) || b.depth) return -1;
	*out_len = b.len;
	return 0;
}

int ks_usteer_send(struct ks_state *s)
{
	uint8_t buf[KS_MAX_PACKET];
	size_t len, i;
	struct sockaddr_in dst;
	int sent = 0, one = 1;

	if (!s->cfg.usteer_enabled || s->udp_fd < 0) return 0;
	if (ks_usteer_encode(s, buf, sizeof(buf), &len)) return -1;
	s->usteer_seq++;
	memset(&dst, 0, sizeof(dst)); dst.sin_family = AF_INET;
	dst.sin_port = htons(16720); dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	setsockopt(s->udp_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
	if (sendto(s->udp_fd, buf, len, 0, (struct sockaddr *) &dst, sizeof(dst)) == (ssize_t) len) sent++;
	for (i = 0; i < s->cfg.n_usteer_peers; i++) {
		if (sendto(s->udp_fd, buf, len, 0, (struct sockaddr *) &s->cfg.usteer_peers[i].addr,
			   sizeof(s->cfg.usteer_peers[i].addr)) == (ssize_t) len) sent++;
	}
	return sent ? 0 : -1;
}

struct av { unsigned int id; size_t raw, padded; const uint8_t *data; size_t len; };

static int next_attr(const uint8_t *buf, size_t len, size_t *off, struct av *a)
{
	uint32_t h;
	if (*off > len || len - *off < 4) return -1;
	h = ks_get_be32(buf + *off); a->raw = h & BLOB_LEN_MASK; a->padded = pad4(a->raw);
	a->id = (h >> BLOB_ID_SHIFT) & 0x7f;
	if (a->raw < 4 || a->padded > len - *off) return -1;
	a->data = buf + *off + 4; a->len = a->raw - 4; *off += a->padded;
	return 0;
}

static int find_typed(const uint8_t *buf, size_t len, unsigned int id, size_t want,
		      const uint8_t **data, size_t *data_len)
{
	size_t off = 0; struct av a; int found = 0;
	while (off < len) {
		if (next_attr(buf, len, &off, &a)) return -1;
		if (a.id != id) continue;
		if (found || (want && a.len != want)) return -1;
		*data = a.data;
		if (data_len) *data_len = a.len;
		found = 1;
	}
	return found;
}

static int valid_attrs(const uint8_t *buf, size_t len)
{
	size_t off = 0;
	struct av a;
	while (off < len) if (next_attr(buf, len, &off, &a)) return -1;
	return off == len ? 0 : -1;
}

int ks_usteer_parse(struct ks_state *s, const uint8_t *buf, size_t len,
		    const struct sockaddr_in *src, uint64_t now)
{
	struct {
		bool set;
		char ssid[KS_MAX_SSID + 1];
		int channel;
		int op_class;
	} update[KS_MAX_FT_PEERS];
	const uint8_t *idp, *seqp, *nodes;
	size_t nodes_len = 0, root_off = 0, off = 0;
	struct av root, node;
	unsigned int count = 0;
	uint32_t id;
	size_t i;

	if (!s || !buf || len < 4 || len > KS_MAX_PACKET ||
	    !src || src->sin_family != AF_INET || !src->sin_addr.s_addr ||
	    next_attr(buf, len, &root_off, &root) || root_off != len || root.id != 0)
		return -1;
	if (find_typed(root.data, root.len, APMSG_ID, 4, &idp, NULL) != 1 ||
	    find_typed(root.data, root.len, APMSG_SEQ, 4, &seqp, NULL) != 1 ||
	    find_typed(root.data, root.len, APMSG_NODES, 0, &nodes, &nodes_len) != 1)
		return -1;
	(void) seqp;
	id = ks_get_be32(idp);
	if (id == s->usteer_id) return 0;
	memset(update, 0, sizeof(update));
	while (off < nodes_len) {
		const uint8_t *name, *freq, *n_assoc, *stations, *ssid, *bssid;
		const uint8_t *channel = NULL, *op_class = NULL;
		size_t name_len = 0, stations_len = 0, ssid_len = 0;

		if (++count > 64 || next_attr(nodes, nodes_len, &off, &node) || node.id != 0 ||
		    find_typed(node.data, node.len, NODE_NAME, 0, &name, &name_len) != 1 ||
		    find_typed(node.data, node.len, NODE_FREQ, 4, &freq, NULL) != 1 ||
		    find_typed(node.data, node.len, NODE_N_ASSOC, 4, &n_assoc, NULL) != 1 ||
		    find_typed(node.data, node.len, NODE_STATIONS, 0, &stations, &stations_len) != 1 ||
		    find_typed(node.data, node.len, NODE_SSID, 0, &ssid, &ssid_len) != 1 ||
		    find_typed(node.data, node.len, NODE_BSSID, 6, &bssid, NULL) != 1 ||
		    !name_len || name_len > KS_MAX_NODE_NAME + 1 || name[name_len - 1] ||
		    !ssid_len || ssid_len > KS_MAX_SSID + 1 || ssid[ssid_len - 1] ||
		    !ks_mac_unicast(bssid) || valid_attrs(stations, stations_len)) return -1;
		(void) freq;
		(void) n_assoc;
		if (find_typed(node.data, node.len, NODE_CHANNEL, 4, &channel, NULL) < 0 ||
		    find_typed(node.data, node.len, NODE_OP_CLASS, 4, &op_class, NULL) < 0)
			return -1;
		for (i = 0; i < s->cfg.n_ft_peers; i++) {
			if (!s->cfg.ft_peers[i].used || !ks_mac_equal(s->cfg.ft_peers[i].bssid, bssid))
				continue;
			if (s->cfg.ft_peers[i].peer_ip.s_addr != src->sin_addr.s_addr)
				continue;
			update[i].set = true;
			memcpy(update[i].ssid, ssid, ssid_len);
			if (channel) update[i].channel = (int32_t) ks_get_be32(channel);
			if (op_class) update[i].op_class = (int32_t) ks_get_be32(op_class);
		}
	}
	for (i = 0; i < s->cfg.n_ft_peers; i++) if (update[i].set) {
		struct ks_ft_peer *p = &s->cfg.ft_peers[i];
		p->learned = true;
		p->last_seen_ms = now;
		strcpy(p->ssid, update[i].ssid);
		p->channel = update[i].channel;
		p->op_class = update[i].op_class;
	}
	return (int) count;
}

void ks_usteer_expire(struct ks_state *s, uint64_t now)
{
	size_t i;
	for (i = 0; i < s->cfg.n_ft_peers; i++) {
		struct ks_ft_peer *p = &s->cfg.ft_peers[i];
		if (!p->learned || now - p->last_seen_ms < s->cfg.peer_ttl_ms) continue;
		p->learned = false;
		p->last_seen_ms = 0;
		p->ssid[0] = 0;
		p->channel = p->op_class = 0;
	}
}

int ks_usteer_receive(struct ks_state *s)
{
	uint8_t buf[KS_MAX_PACKET];
	struct sockaddr_in src = {0};
	socklen_t sl = sizeof(src);
	ssize_t n;
	int rc;

	n = recvfrom(s->udp_fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *) &src, &sl);
	if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
	rc = ks_usteer_parse(s, buf, (size_t) n, &src, ks_now_ms());
	ks_secure_clear(buf, (size_t) n);
	if (rc < 0) return 1;
	return 1;
}
