#define _GNU_SOURCE
#include "keensteer.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/wireless.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void seterr(char *err, size_t len, const char *fmt, ...)
{
	va_list ap;
	if (!err || !len) return;
	va_start(ap, fmt);
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
	vsnprintf(err, len, fmt, ap);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
	va_end(ap);
}

static char *trim(char *s)
{
	char *e;
	while (isspace((unsigned char) *s)) s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char) e[-1])) e--;
	*e = 0;
	return s;
}

static bool parse_bool(const char *s, bool *v)
{
	if (!strcasecmp(s, "1") || !strcasecmp(s, "yes") || !strcasecmp(s, "true")) {
		*v = true; return true;
	}
	if (!strcasecmp(s, "0") || !strcasecmp(s, "no") || !strcasecmp(s, "false")) {
		*v = false; return true;
	}
	return false;
}

static bool parse_u32(const char *s, unsigned int lo, unsigned int hi,
		      unsigned int *v)
{
	char *end;
	unsigned long n;
	errno = 0;
	n = strtoul(s, &end, 10);
	if (errno || *end || n < lo || n > hi) return false;
	*v = (unsigned int) n;
	return true;
}

void ks_config_defaults(struct ks_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	strcpy(cfg->path, "/opt/etc/keensteer.conf");
	cfg->usteer_enabled = true;
	cfg->ft_enabled = false;
	cfg->usteer_interval_ms = 1000;
	cfg->station_ttl_ms = 120000;
	cfg->peer_ttl_ms = 15000;
	cfg->kdp_timeout_ms = 1500;
	strcpy(cfg->rrb_key_file, "/opt/etc/keensteer.rrb.key");
}

static int add_usteer_peer(struct ks_config *cfg, const char *s)
{
	struct ks_usteer_peer *p;
	char copy[128], *colon;
	unsigned int port = 16720;

	if (cfg->n_usteer_peers >= KS_MAX_USTEER_PEERS || strlen(s) >= sizeof(copy))
		return -1;
	strcpy(copy, s);
	colon = strrchr(copy, ':');
	if (colon && strchr(copy, '.') && strchr(colon + 1, ':') == NULL) {
		unsigned int n;
		*colon++ = 0;
		if (!parse_u32(colon, 1, 65535, &n)) return -1;
		port = n;
	}
	p = &cfg->usteer_peers[cfg->n_usteer_peers];
	memset(p, 0, sizeof(*p));
	p->addr.sin_family = AF_INET;
	p->addr.sin_port = htons((uint16_t) port);
	if (inet_pton(AF_INET, copy, &p->addr.sin_addr) != 1)
		return -1;
	p->used = true;
	cfg->n_usteer_peers++;
	return 0;
}

/* ft_peer=bssid,transport-mac,ipv4,r1kh-id-or-empty,r0kh-id */
static int add_ft_peer(struct ks_config *cfg, char *s)
{
	struct ks_ft_peer *p;
	char *f[5];
	size_t n;
	uint32_t ip;
	int i;

	if (cfg->n_ft_peers >= KS_MAX_FT_PEERS) return -1;
	for (i = 0; i < 5; i++) f[i] = strsep(&s, ",");
	if (s || !f[0] || !f[1] || !f[2]) return -1;
	for (i = 0; i < 5 && f[i]; i++) f[i] = trim(f[i]);
	p = &cfg->ft_peers[cfg->n_ft_peers];
	memset(p, 0, sizeof(*p));
	if (!ks_mac_parse(f[0], p->bssid) || !ks_mac_parse(f[1], p->transport))
		return -1;
	if (inet_pton(AF_INET, f[2], &p->peer_ip) != 1) return -1;
	ip = ntohl(p->peer_ip.s_addr);
	if (!ip || ip == UINT32_MAX || (ip >> 24) == 127 || (ip >> 28) == 14)
		return -1;
	if (f[3] && *f[3]) {
		if (!ks_mac_parse(f[3], p->r1kh_id)) return -1;
	} else {
		memcpy(p->r1kh_id, p->bssid, 6);
	}
	if (!f[4] || !*f[4] || strlen(f[4]) > KS_MAX_R0KH_ID) return -1;
	strcpy(p->r0kh_id, f[4]);
	p->r0kh_id_len = strlen(f[4]);
	for (n = 0; n < cfg->n_ft_peers; n++)
		if (cfg->ft_peers[n].r0kh_id_len == p->r0kh_id_len &&
		    !memcmp(cfg->ft_peers[n].r0kh_id, p->r0kh_id, p->r0kh_id_len))
			return -1;
	p->used = p->static_config = true;
	cfg->n_ft_peers++;
	return 0;
}

/* bss=ifname,name,ssid,bssid,channel,opclass[,r1kh-id[,r0kh-id]] */
static int add_bss(struct ks_config *cfg, char *s)
{
	struct ks_bss *b;
	char *f[8];
	unsigned int channel, opclass;
	int i;

	if (cfg->n_bss >= KS_MAX_BSS) return -1;
	for (i = 0; i < 8; i++) f[i] = strsep(&s, ",");
	if (s || !f[5]) return -1;
	for (i = 0; i < 8 && f[i]; i++) f[i] = trim(f[i]);
	if (!*f[0] || strlen(f[0]) >= IFNAMSIZ || !*f[1] ||
	    strlen(f[1]) > KS_MAX_NODE_NAME || strlen(f[2]) > KS_MAX_SSID ||
	    !parse_u32(f[4], 1, 233, &channel) ||
	    !parse_u32(f[5], 1, 255, &opclass)) return -1;
	b = &cfg->bss[cfg->n_bss];
	memset(b, 0, sizeof(*b));
	strcpy(b->ifname, f[0]); strcpy(b->name, f[1]); strcpy(b->ssid, f[2]);
	if (!ks_mac_parse(f[3], b->bssid)) return -1;
	if (f[6] && *f[6]) {
		if (!ks_mac_parse(f[6], b->r1kh_id)) return -1;
	} else {
		memcpy(b->r1kh_id, b->bssid, 6);
	}
	if (f[7] && *f[7]) {
		if (strlen(f[7]) > KS_MAX_R0KH_ID) return -1;
		strcpy(b->r0kh_id, f[7]); b->r0kh_id_len = strlen(f[7]);
	}
	b->channel = (int) channel; b->op_class = (int) opclass;
	b->band = channel <= 14 ? KS_BAND_2GHZ : KS_BAND_5GHZ;
	b->freq = channel == 14 ? 2484 : (channel <= 14 ? 2407 + 5 * (int) channel : 5000 + 5 * (int) channel);
	b->noise = -95; b->max_assoc = 128; b->active = true;
	cfg->n_bss++;
	return 0;
}

int ks_config_load(struct ks_config *cfg, const char *path, char *err, size_t err_len)
{
	FILE *f;
	char line[KS_MAX_CONFIG_LINE + 2];
	unsigned int lineno = 0;

	if (strlen(path) >= sizeof(cfg->path)) {
		seterr(err, err_len, "configuration path too long"); return -1;
	}
	f = fopen(path, "r");
	if (!f) { seterr(err, err_len, "%s: %s", path, strerror(errno)); return -1; }
	strcpy(cfg->path, path);
	while (fgets(line, sizeof(line), f)) {
		char *key, *val, *hash, *eq;
		lineno++;
		if (!strchr(line, '\n') && !feof(f)) {
			seterr(err, err_len, "%s:%u: line too long", path, lineno); goto bad;
		}
		hash = strchr(line, '#'); if (hash) *hash = 0;
		key = trim(line); if (!*key) continue;
		eq = strchr(key, '='); if (!eq) { seterr(err, err_len, "%s:%u: expected key=value", path, lineno); goto bad; }
		*eq++ = 0; val = trim(eq); key = trim(key);
		if (!strcmp(key, "interface")) {
			if (!*val || strlen(val) >= IFNAMSIZ) goto value_bad;
			strcpy(cfg->transport_if, val);
		} else if (!strcmp(key, "usteer")) {
			if (!parse_bool(val, &cfg->usteer_enabled)) goto value_bad;
		} else if (!strcmp(key, "ft")) {
			if (!parse_bool(val, &cfg->ft_enabled)) goto value_bad;
		} else if (!strcmp(key, "debug")) {
			if (!parse_bool(val, &cfg->debug)) goto value_bad;
		} else if (!strcmp(key, "usteer_interval")) {
			if (!parse_u32(val, 250, 60000, &cfg->usteer_interval_ms)) goto value_bad;
		} else if (!strcmp(key, "station_ttl")) {
			if (!parse_u32(val, 1000, 3600000, &cfg->station_ttl_ms)) goto value_bad;
		} else if (!strcmp(key, "peer_ttl")) {
			if (!parse_u32(val, 1000, 300000, &cfg->peer_ttl_ms)) goto value_bad;
		} else if (!strcmp(key, "kdp_timeout")) {
			if (!parse_u32(val, 100, 30000, &cfg->kdp_timeout_ms)) goto value_bad;
		} else if (!strcmp(key, "rrb_key_file")) {
			if (!*val || strlen(val) >= sizeof(cfg->rrb_key_file)) goto value_bad;
			strcpy(cfg->rrb_key_file, val);
		} else if (!strcmp(key, "usteer_peer")) {
			if (add_usteer_peer(cfg, val)) goto value_bad;
		} else if (!strcmp(key, "ft_peer")) {
			if (add_ft_peer(cfg, val)) goto value_bad;
		} else if (!strcmp(key, "bss")) {
			if (add_bss(cfg, val)) goto value_bad;
		} else {
			seterr(err, err_len, "%s:%u: unknown option '%s'", path, lineno, key); goto bad;
		}
		continue;
value_bad:
		seterr(err, err_len, "%s:%u: invalid value for '%s'", path, lineno, key); goto bad;
	}
	if (ferror(f)) { seterr(err, err_len, "%s: read error", path); goto bad; }
	fclose(f);
	if (!cfg->transport_if[0]) {
		seterr(err, err_len, "%s: interface is required", path); return -1;
	}
	if (!cfg->n_bss) {
		seterr(err, err_len, "%s: at least one bss is required", path); return -1;
	}
	if (cfg->ft_enabled && !cfg->n_ft_peers) {
		seterr(err, err_len, "%s: ft requires at least one ft_peer", path); return -1;
	}
	if (cfg->ft_enabled) for (size_t i = 0; i < cfg->n_bss; i++)
		if (!cfg->bss[i].r0kh_id_len) {
			seterr(err, err_len, "%s: ft requires a local R0KH-ID for every bss", path);
			return -1;
		}
	return 0;
bad:
	fclose(f);
	return -1;
}

static int hex_decode(const char *s, uint8_t *out, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		unsigned int v;
		if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t) v;
	}
	return s[n * 2] ? -1 : 0;
}

int ks_load_rrb_key(const char *path, uint8_t key[32], char *err, size_t err_len)
{
	struct stat st;
	FILE *f;
	char line[80], *s;
	uint8_t old[16];
	int fd, rc = -1;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		if (fd >= 0) close(fd);
		seterr(err, err_len, "RRB key file is not a regular file"); return -1;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		close(fd);
		seterr(err, err_len, "RRB key file must not be accessible by group/other"); return -1;
	}
	if ((geteuid() == 0 && st.st_uid != 0) || (geteuid() != 0 && st.st_uid != geteuid())) {
		close(fd);
		seterr(err, err_len, "RRB key file has unexpected owner"); return -1;
	}
	f = fdopen(fd, "r");
	if (!f) { close(fd); seterr(err, err_len, "cannot open RRB key file"); return -1; }
	if (!fgets(line, sizeof(line), f) || (fgets((char[2]){0}, 2, f) != NULL)) {
		seterr(err, err_len, "RRB key file must contain one line"); goto out;
	}
	s = trim(line);
	if (strlen(s) == 32 && !hex_decode(s, old, 16) && !ks_rrb_expand_key(old, key)) {
		rc = 0;
	} else if (strlen(s) == 64 && !hex_decode(s, key, 32)) {
		rc = 0;
	} else {
		seterr(err, err_len, "RRB key must encode 16 or 32 bytes");
	}
out:
	ks_secure_clear(line, sizeof(line)); ks_secure_clear(old, sizeof(old));
	if (rc) ks_secure_clear(key, 32);
	fclose(f);
	return rc;
}

static int ifindex_from_name(int fd, const char *name)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, name, strlen(name) + 1);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) return 0;
	return ifr.ifr_ifindex;
}

static int channel_from_freq(int mhz)
{
	if (mhz == 2484) return 14;
	if (mhz >= 2412 && mhz <= 2472) return (mhz - 2407) / 5;
	if (mhz >= 5000 && mhz <= 7115) return (mhz - 5000) / 5;
	return 0;
}

static int opclass_from_channel(int channel, int current)
{
	switch (current) {
	case 128:
	case 129:
		return current;
	case 83: case 84: case 116: case 117: case 119: case 120:
	case 122: case 123: case 126: case 127:
		if (channel >= 1 && channel <= 9) return 83;
		if (channel >= 10 && channel <= 13) return 84;
		if (channel == 36 || channel == 44) return 116;
		if (channel == 40 || channel == 48) return 117;
		if (channel == 52 || channel == 60) return 119;
		if (channel == 56 || channel == 64) return 120;
		if (channel == 100 || channel == 108 || channel == 116 ||
		    channel == 124 || channel == 132 || channel == 140) return 122;
		if (channel == 104 || channel == 112 || channel == 120 ||
		    channel == 128 || channel == 136 || channel == 144) return 123;
		if (channel == 149 || channel == 157) return 126;
		if (channel == 153 || channel == 161) return 127;
		return current;
	case 81: case 82: case 115: case 118: case 121: case 124: case 125:
		if (channel == 14) return 82;
		if (channel >= 1 && channel <= 13) return 81;
		if (channel >= 36 && channel <= 48) return 115;
		if (channel >= 52 && channel <= 64) return 118;
		if (channel >= 100 && channel <= 144) return 121;
		if (channel >= 149 && channel <= 161) return 124;
		if (channel == 165) return 125;
		return current;
	default:
		return current;
	}
}

static int discover_one(int fd, struct ks_bss *b)
{
	struct iwreq wrq;
	char essid[KS_MAX_SSID + 1];
	int e, mode;

	b->active = b->mtk_kdp = false;
	memset(&wrq, 0, sizeof(wrq));
	memcpy(wrq.ifr_name, b->ifname, strlen(b->ifname) + 1);
	b->ifindex = ifindex_from_name(fd, b->ifname);
	if (!b->ifindex || ioctl(fd, SIOCGIWMODE, &wrq) < 0) return -1;
	mode = wrq.u.mode;
	if (mode != IW_MODE_MASTER) return -1;

	memset(&wrq, 0, sizeof(wrq));
	memcpy(wrq.ifr_name, b->ifname, strlen(b->ifname) + 1);
	if (ioctl(fd, SIOCGIFHWADDR, &wrq) == 0 && !ks_mac_unicast(b->bssid))
		memcpy(b->bssid, wrq.u.ap_addr.sa_data, 6);
	if (!ks_mac_unicast(b->r1kh_id) && ks_mac_unicast(b->bssid))
		memcpy(b->r1kh_id, b->bssid, 6);

	memset(&wrq, 0, sizeof(wrq));
	memcpy(wrq.ifr_name, b->ifname, strlen(b->ifname) + 1);
	memset(essid, 0, sizeof(essid));
	wrq.u.essid.pointer = essid;
	wrq.u.essid.length = sizeof(essid) - 1;
	if (ioctl(fd, SIOCGIWESSID, &wrq) == 0) {
		size_t n = wrq.u.essid.length;
		if (n > KS_MAX_SSID) n = KS_MAX_SSID;
		memcpy(b->ssid, essid, n);
		b->ssid[n] = 0;
	}

	memset(&wrq, 0, sizeof(wrq));
	memcpy(wrq.ifr_name, b->ifname, strlen(b->ifname) + 1);
	if (ioctl(fd, SIOCGIWFREQ, &wrq) == 0) {
		int new_channel = 0, new_freq = 0;

		if (wrq.u.freq.e == 0 && wrq.u.freq.m > 0 && wrq.u.freq.m <= 233) {
			new_channel = wrq.u.freq.m;
		} else if (wrq.u.freq.e >= -3 && wrq.u.freq.e <= 9) {
			long long hz = wrq.u.freq.m;
			for (e = wrq.u.freq.e; e > 0; e--) hz *= 10;
			for (e = wrq.u.freq.e; e < 0; e++) hz /= 10;
			if (hz > 100000000) new_freq = (int) (hz / 1000000);
		}
		if (!new_channel && new_freq) new_channel = channel_from_freq(new_freq);
		if (new_channel) {
			b->channel = new_channel;
			b->freq = new_freq ? new_freq :
				(new_channel == 14 ? 2484 :
				 (new_channel <= 14 ? 2407 + 5 * new_channel :
				  5000 + 5 * new_channel));
			b->op_class = opclass_from_channel(b->channel, b->op_class);
		}
	}
	if (b->channel >= 1 && b->channel <= 14) b->band = KS_BAND_2GHZ;
	else if (b->channel >= 30 && b->channel <= 177) b->band = KS_BAND_5GHZ;
	else b->band = KS_BAND_UNKNOWN;
	if (!b->name[0]) snprintf(b->name, sizeof(b->name), "keenetic.%s", b->ifname);
	if (!b->max_assoc) b->max_assoc = 128;
	if (!b->noise) b->noise = -95;
	b->active = b->ssid[0] && ks_mac_unicast(b->bssid) &&
		b->band != KS_BAND_UNKNOWN && b->freq && b->channel && b->op_class;
	b->mtk_kdp = b->active;
	return b->active ? 0 : -1;
}

int ks_topology_discover(struct ks_state *s)
{
	struct ifreq ifr;
	int fd, active = 0;
	size_t i;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, s->cfg.transport_if, strlen(s->cfg.transport_if) + 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) ||
	    !ks_mac_unicast((uint8_t *) ifr.ifr_hwaddr.sa_data)) {
		close(fd);
		return -1;
	}
	memcpy(s->transport_mac, ifr.ifr_hwaddr.sa_data, 6);
	s->transport_ifindex = ifindex_from_name(fd, s->cfg.transport_if);
	if (!s->transport_ifindex) {
		close(fd);
		return -1;
	}
	for (i = 0; i < s->cfg.n_bss; i++)
		if (!discover_one(fd, &s->cfg.bss[i])) active++;
	close(fd);
	return active ? 0 : -1;
}

struct ks_station *ks_station_get(struct ks_state *s, const uint8_t addr[6],
				  bool create)
{
	struct ks_station *free_slot = NULL;
	size_t i;

	for (i = 0; i < KS_MAX_STA; i++) {
		if (s->stations[i].used && ks_mac_equal(s->stations[i].addr, addr))
			return &s->stations[i];
		if (!s->stations[i].used && !free_slot) free_slot = &s->stations[i];
	}
	if (!create || !free_slot || !ks_mac_unicast(addr)) return NULL;
	memset(free_slot, 0, sizeof(*free_slot));
	free_slot->used = true;
	memcpy(free_slot->addr, addr, 6);
	free_slot->bss_index = -1;
	return free_slot;
}

void ks_station_expire(struct ks_state *s, uint64_t now)
{
	size_t i;

	for (i = 0; i < KS_MAX_STA; i++) {
		struct ks_station *st = &s->stations[i];
		size_t b;
		bool any = false;

		if (!st->used) continue;
		for (b = 0; b < s->cfg.n_bss; b++) {
			if (st->seen_ms[b] && now - st->seen_ms[b] >= s->cfg.station_ttl_ms)
				st->seen_ms[b] = 0;
			any |= st->seen_ms[b] != 0;
		}
		if (!any && !st->connected) memset(st, 0, sizeof(*st));
	}
}

int ks_bss_by_ifindex(const struct ks_state *s, int ifindex)
{
	size_t i;
	for (i = 0; i < s->cfg.n_bss; i++)
		if (s->cfg.bss[i].active && s->cfg.bss[i].ifindex == ifindex) return (int) i;
	return -1;
}

int ks_bss_by_bssid(const struct ks_state *s, const uint8_t bssid[6])
{
	size_t i;
	for (i = 0; i < s->cfg.n_bss; i++)
		if (s->cfg.bss[i].active && ks_mac_equal(s->cfg.bss[i].bssid, bssid)) return (int) i;
	return -1;
}

int ks_bss_by_r1kh(const struct ks_state *s, const uint8_t r1kh[6])
{
	size_t i;
	for (i = 0; i < s->cfg.n_bss; i++)
		if (s->cfg.bss[i].active && ks_mac_equal(s->cfg.bss[i].r1kh_id, r1kh)) return (int) i;
	return -1;
}
