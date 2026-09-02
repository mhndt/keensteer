#define _GNU_SOURCE
#include "keensteer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define OID_BNDSTRG_MSG 0x0950
#define BNDSTRG_MSG_LEN 112
#define BNDSTRG_RSSI_OFF 71
#define BNDSTRG_MAC_OFF 88
#define BNDSTRG_UPDATE_ACTION 3
#define BNDSTRG_BAND_OFF 4
#define BNDSTRG_UPDATE_CONNECTED_OFF 95
#define BNDSTRG_UPDATE_MAC_OFF 88
#define BNDSTRG_BAND_5GHZ 1
#define BNDSTRG_BAND_2GHZ 2
#define LOAD_UPDATE_MS 3000
#define SINK_REPROBE_MS 30000

#ifdef KS_TEST
static uint8_t test_rrb[KS_MAX_PACKET], test_ioctl[KS_KDP_WRAPPER_LEN];
static size_t test_rrb_len, test_ioctl_len;
static unsigned int test_rrb_count, test_ioctl_count;
static uint16_t test_oid;
static int test_bss;
#endif

static int nonblock(int fd)
{
	int f = fcntl(fd, F_GETFL, 0);
	return f < 0 || fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0 ? -1 : 0;
}

static bool sink_probe(struct in_addr addr)
{
	struct sockaddr_in sin;
	struct pollfd pfd;
	socklen_t len;
	int fd, error = 0;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || nonblock(fd)) { if (fd >= 0) close(fd); return false; }
	memset(&sin, 0, sizeof(sin)); sin.sin_family = AF_INET;
	sin.sin_port = htons(3517); sin.sin_addr = addr;
	if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) && errno != EINPROGRESS) {
		close(fd); return false;
	}
	pfd = (struct pollfd) { fd, POLLOUT, 0 };
	if (poll(&pfd, 1, 500) != 1) { close(fd); return false; }
	len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) error = errno;
	close(fd);
	return error == 0;
}

static bool local_ipv4(struct in_addr addr)
{
	struct ifaddrs *all, *p;
	bool found = false;
	if (getifaddrs(&all)) return true;
	for (p = all; p; p = p->ifa_next)
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET &&
		    ((struct sockaddr_in *) p->ifa_addr)->sin_addr.s_addr == addr.s_addr) {
			found = true; break;
		}
	freeifaddrs(all);
	return found;
}

int ks_backend_open(struct ks_state *s)
{
	struct sockaddr_nl nl;
	struct sockaddr_in sin;
	int one = 1;

	s->udp_fd = s->packet_fd = s->netlink_fd = s->ioctl_fd = -1;
	if (s->cfg.ft_enabled || s->cfg.usteer_enabled)
		s->ioctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s->cfg.ft_enabled) {
		s->packet_fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
		if (s->ioctl_fd < 0 || s->packet_fd < 0 || nonblock(s->packet_fd)) goto bad;
	}
	if (s->cfg.usteer_enabled) {
		s->netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
		s->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (s->netlink_fd < 0 || s->udp_fd < 0 || nonblock(s->netlink_fd) ||
		    nonblock(s->udp_fd)) goto bad;
		memset(&nl, 0, sizeof(nl));
		nl.nl_family = AF_NETLINK;
		nl.nl_groups = RTMGRP_LINK;
		if (bind(s->netlink_fd, (struct sockaddr *) &nl, sizeof(nl))) goto bad;
		setsockopt(s->udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (setsockopt(s->udp_fd, SOL_SOCKET, SO_BINDTODEVICE,
			       s->cfg.transport_if, strlen(s->cfg.transport_if) + 1)) goto bad;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(16720);
		if (bind(s->udp_fd, (struct sockaddr *) &sin, sizeof(sin))) goto bad;
	}
	if (s->cfg.ft_enabled) for (size_t i = 0; i < s->cfg.n_ft_peers; i++) {
		struct ks_ft_peer *p = &s->cfg.ft_peers[i];
		char ip[INET_ADDRSTRLEN];
		p->sink_ready = !local_ipv4(p->peer_ip) && sink_probe(p->peer_ip);
		if (!p->sink_ready) {
			inet_ntop(AF_INET, &p->peer_ip, ip, sizeof(ip));
			ks_log(KS_LOG_WARN, "KDP source queries disabled for %s: TCP/3517 unavailable", ip);
		}
	}
	s->next_sink_probe_ms = ks_now_ms() + SINK_REPROBE_MS;
	return 0;
bad:
	ks_backend_close(s); return -1;
}

void ks_backend_update_load(struct ks_state *s)
{
	uint64_t now = ks_now_ms();
	size_t i;

	if (!s->cfg.usteer_enabled || now < s->next_load_ms) return;
	s->next_load_ms = now + LOAD_UPDATE_MS;
	for (i = 0; i < s->cfg.n_bss; i++) {
		struct ks_bss *b = &s->cfg.bss[i];
		uint8_t response[8] = {0};
		struct iwreq wrq;

		b->load = 0;
		if (!b->active || s->ioctl_fd < 0) continue;
		memset(&wrq, 0, sizeof(wrq));
		memcpy(wrq.ifr_name, b->ifname, strlen(b->ifname) + 1);
		wrq.u.data.pointer = response; wrq.u.data.length = sizeof(response);
		if (ioctl(s->ioctl_fd, KS_MTK_LOAD_IOCTL, &wrq) < 0 ||
		    wrq.u.data.length != sizeof(response) || response[1] > 4 ||
		    response[2] != b->channel || response[6] > 100)
			continue;
		b->load = response[6];
	}
}

void ks_backend_reprobe(struct ks_state *s, uint64_t now)
{
	size_t i, n;

	if (!s->cfg.ft_enabled || now < s->next_sink_probe_ms || !s->cfg.n_ft_peers)
		return;
	s->next_sink_probe_ms = now + SINK_REPROBE_MS;
	for (n = 0; n < s->cfg.n_ft_peers; n++) {
		bool ready;
		char ip[INET_ADDRSTRLEN];

		i = (s->sink_probe_cursor + n) % s->cfg.n_ft_peers;
		if (!s->cfg.ft_peers[i].used) continue;
		s->sink_probe_cursor = (unsigned int) ((i + 1) % s->cfg.n_ft_peers);
		ready = !local_ipv4(s->cfg.ft_peers[i].peer_ip) &&
			sink_probe(s->cfg.ft_peers[i].peer_ip);
		if (ready == s->cfg.ft_peers[i].sink_ready) break;
		s->cfg.ft_peers[i].sink_ready = ready;
		inet_ntop(AF_INET, &s->cfg.ft_peers[i].peer_ip, ip, sizeof(ip));
		ks_log(ready ? KS_LOG_INFO : KS_LOG_WARN,
		       "KDP source queries %s for %s", ready ? "enabled" : "disabled", ip);
		break;
	}
}

void ks_backend_close(struct ks_state *s)
{
	int *fds[] = { &s->udp_fd, &s->packet_fd, &s->netlink_fd, &s->ioctl_fd };
	size_t i;
	for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
		if (*fds[i] >= 0) { close(*fds[i]); *fds[i] = -1; }
}

static int priv_ioctl(struct ks_state *s, int bss, uint16_t oid, uint8_t *buf, size_t len)
{
	struct iwreq wrq;
	if (bss < 0 || (size_t) bss >= s->cfg.n_bss ||
	    !s->cfg.bss[bss].mtk_kdp || len > UINT16_MAX) return -1;
#ifdef KS_TEST
	if (s->ioctl_fd == -2 && len <= sizeof(test_ioctl)) {
		memcpy(test_ioctl, buf, len); test_ioctl_len = len;
		test_oid = oid; test_bss = bss; test_ioctl_count++; return 0;
	}
#endif
	if (s->ioctl_fd < 0) return -1;
	memset(&wrq, 0, sizeof(wrq));
	memcpy(wrq.ifr_name, s->cfg.bss[bss].ifname,
	       strlen(s->cfg.bss[bss].ifname) + 1);
	wrq.u.data.pointer = buf; wrq.u.data.length = (uint16_t) len; wrq.u.data.flags = oid;
	return ioctl(s->ioctl_fd, KS_MTK_PRIV_IOCTL, &wrq) < 0 ? -1 : 0;
}

int ks_backend_ft_query(struct ks_state *s, int bss_index,
			const struct ks_kdp_element *element, uint32_t correlation)
{
	uint8_t req[KS_KDP_WRAPPER_LEN]; int rc;
	size_t i;
	for (i = 0; i < s->cfg.n_ft_peers; i++)
		if (s->cfg.ft_peers[i].peer_ip.s_addr == correlation && s->cfg.ft_peers[i].sink_ready)
			break;
	if (i == s->cfg.n_ft_peers || ks_kdp_build_wrapper(correlation, element, req)) return -1;
	rc = priv_ioctl(s, bss_index, KS_OID_FT_QUERY, req, sizeof(req));
	ks_secure_clear(req, sizeof(req)); return rc;
}

int ks_backend_ft_insert(struct ks_state *s, int bss_index, struct in_addr source,
			 const struct ks_kdp_element *element)
{
	uint8_t req[KS_KDP_WRAPPER_LEN]; int rc;
	if (!source.s_addr || ks_kdp_build_wrapper(source.s_addr, element, req)) return -1;
	rc = priv_ioctl(s, bss_index, KS_OID_FT_INSERT, req, sizeof(req));
	ks_secure_clear(req, sizeof(req));
	return rc;
}

int ks_backend_send_rrb(struct ks_state *s, const uint8_t dst[6],
			const uint8_t *frame, size_t len)
{
	struct sockaddr_ll ll;
	if (!frame || len < 20 || len > KS_MAX_PACKET || s->transport_ifindex <= 0 ||
	    !ks_mac_equal(frame, dst)) return -1;
#ifdef KS_TEST
	if (s->packet_fd == -2) {
		memcpy(test_rrb, frame, len); test_rrb_len = len; test_rrb_count++; return 0;
	}
#endif
	memset(&ll, 0, sizeof(ll)); ll.sll_family = AF_PACKET; ll.sll_ifindex = s->transport_ifindex;
	ll.sll_protocol = htons(KS_ETH_P_RRB); ll.sll_halen = 6; memcpy(ll.sll_addr, dst, 6);
	return sendto(s->packet_fd, frame, len, 0, (struct sockaddr *) &ll, sizeof(ll)) == (ssize_t) len ? 0 : -1;
}

static int handle_packet(struct ks_state *s, const uint8_t *frame, size_t n,
			 int ifindex)
{
	struct ks_kdp_element e; uint32_t corr; uint8_t sta[6]; int bss;

	if (n < 14) return 0;
	if (frame[12] == 0xee && frame[13] == 0xee) {
		if (!ks_kdp_parse_signal50(frame, n, ifindex, &e, sta)) {
			bss = ks_bss_by_ifindex(s, ifindex);
			if (bss >= 0) {
				struct ks_station *st = ks_station_get(s, sta, true);
				if (st) { st->connected = true; st->bss_index = bss; st->connected_ms = ks_now_ms();
					st->seen_2ghz |= s->cfg.bss[bss].band == KS_BAND_2GHZ;
					st->seen_5ghz |= s->cfg.bss[bss].band == KS_BAND_5GHZ; }
				ks_kdp_prewarm_event(s, bss, &e);
			}
		} else if (n > 0x20 && frame[0x20] == 0xa0) {
			if (!ks_kdp_parse_signala0(frame, n, &e)) {
				bss = ks_bss_by_r1kh(s, ks_kdp_r1kh(&e));
				if (bss >= 0) ks_rrb_send_pull(s, bss, &e);
			}
		} else if (!ks_kdp_parse_signala1(frame, n, &corr, &e))
			ks_kdp_handle_response(s, ifindex, corr, &e);
		ks_secure_clear(&e, sizeof(e));
	} else if (frame[12] == 0x88 && frame[13] == 0xb7 &&
		   ifindex == s->transport_ifindex)
		ks_rrb_handle_frame(s, frame, n);
	return 1;
}

int ks_backend_handle_packet(struct ks_state *s)
{
	uint8_t frame[KS_MAX_PACKET];
	struct sockaddr_ll ll; socklen_t sl = sizeof(ll); ssize_t n;
	int rc;

	memset(&ll, 0, sizeof(ll));
	n = recvfrom(s->packet_fd, frame, sizeof(frame), MSG_DONTWAIT,
		     (struct sockaddr *) &ll, &sl);
	if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
	if (ll.sll_pkttype == PACKET_OUTGOING) return 1;
	rc = handle_packet(s, frame, (size_t) n, ll.sll_ifindex);
	ks_secure_clear(frame, (size_t) n);
	if (rc < 0) return rc;
	return 1;
}

static int bndstrg_parse(const uint8_t *p, size_t len, uint8_t mac[6], int *signal)
{
	int rssi = -127, i;
	if (len != BNDSTRG_MSG_LEN || (p[0] != 0x01 && p[0] != 0x15) ||
	    !ks_mac_unicast(p + BNDSTRG_MAC_OFF)) return -1;
	for (i = 0; i < 3; i++) { int v = (int8_t) p[BNDSTRG_RSSI_OFF + i]; if (v >= -95 && v <= -30 && v > rssi) rssi = v; }
	if (rssi == -127) return -1;
	memcpy(mac, p + BNDSTRG_MAC_OFF, 6);
	*signal = rssi;
	return 0;
}

#ifdef KS_TEST
int ks_mtk_test_bndstrg(const uint8_t *buf, size_t len, uint8_t mac[6], int *signal)
{
	if (!buf || !mac || !signal) return -1;
	return bndstrg_parse(buf, len, mac, signal);
}
#endif

static void assoc_event(struct ks_state *s, int ifindex, const uint8_t mac[6], bool connected);

static int bndstrg_bss(const struct ks_state *s, uint8_t band)
{
	enum ks_band want;
	int found = -1;
	size_t i;

	if (band == BNDSTRG_BAND_5GHZ) want = KS_BAND_5GHZ;
	else if (band == BNDSTRG_BAND_2GHZ) want = KS_BAND_2GHZ;
	else return -1;

	for (i = 0; i < s->cfg.n_bss; i++) {
		if (!s->cfg.bss[i].active || s->cfg.bss[i].band != want) continue;
		if (found >= 0) return -1;
		found = (int) i;
	}
	return found;
}

static void assoc_bss_event(struct ks_state *s, int bss, const uint8_t mac[6], bool connected)
{
	struct ks_station *st;

	if (bss < 0 || !ks_mac_unicast(mac)) return;
	st = ks_station_get(s, mac, connected); if (!st) return;
	if (connected) {
		st->connected = true; st->bss_index = bss; st->connected_ms = ks_now_ms();
		st->seen_2ghz |= s->cfg.bss[bss].band == KS_BAND_2GHZ;
		st->seen_5ghz |= s->cfg.bss[bss].band == KS_BAND_5GHZ;
	} else if (st->connected && st->bss_index == bss) {
		st->connected = false; st->connected_ms = ks_now_ms();
	}
}

static void bndstrg_event(struct ks_state *s, int ifindex, const uint8_t *p, size_t len)
{
	struct ks_station *st;
	uint8_t mac[6];
	int rssi, bss;

	(void) ifindex;
	if (len == BNDSTRG_MSG_LEN && p[0] == BNDSTRG_UPDATE_ACTION &&
	    p[BNDSTRG_UPDATE_CONNECTED_OFF] <= 1 &&
	    ks_mac_unicast(p + BNDSTRG_UPDATE_MAC_OFF)) {
		bss = bndstrg_bss(s, p[BNDSTRG_BAND_OFF]);
		if (bss >= 0)
			assoc_bss_event(s, bss, p + BNDSTRG_UPDATE_MAC_OFF,
					p[BNDSTRG_UPDATE_CONNECTED_OFF] != 0);
		return;
	}

	if (bndstrg_parse(p, len, mac, &rssi)) return;
	bss = bndstrg_bss(s, p[BNDSTRG_BAND_OFF]); if (bss < 0) return;
	st = ks_station_get(s, mac, true); if (!st) return;
	st->signal[bss] = rssi; st->seen_ms[bss] = ks_now_ms();
	st->seen_2ghz |= s->cfg.bss[bss].band == KS_BAND_2GHZ;
	st->seen_5ghz |= s->cfg.bss[bss].band == KS_BAND_5GHZ;
}

static void assoc_event(struct ks_state *s, int ifindex, const uint8_t mac[6], bool connected)
{
	assoc_bss_event(s, ks_bss_by_ifindex(s, ifindex), mac, connected);
}

static int wireless_events(struct ks_state *s, int ifindex, const uint8_t *w, size_t left)
{
	size_t off = 0;
	int handled = 0;
	while (left - off >= IW_EV_LCP_PK_LEN) {
		uint16_t elen, cmd;
		memcpy(&elen, w + off, 2); memcpy(&cmd, w + off + 2, 2);
		if (elen < IW_EV_LCP_PK_LEN || elen > left - off) return -1;
		if (cmd == IWEVCUSTOM && elen >= IW_EV_POINT_PK_LEN) {
			uint16_t dlen, flags;
			memcpy(&dlen, w + off + 4, 2); memcpy(&flags, w + off + 6, 2);
			if (flags == OID_BNDSTRG_MSG && dlen <= elen - IW_EV_POINT_PK_LEN) {
				bndstrg_event(s, ifindex, w + off + IW_EV_POINT_PK_LEN, dlen); handled++;
			}
		} else if ((cmd == IWEVREGISTERED || cmd == IWEVEXPIRED) &&
			   elen >= IW_EV_ADDR_PK_LEN) {
			uint16_t family;
			memcpy(&family, w + off + IW_EV_LCP_PK_LEN, 2);
			if (family == ARPHRD_ETHER) {
				assoc_event(s, ifindex, w + off + IW_EV_LCP_PK_LEN + 2,
					    cmd == IWEVREGISTERED); handled++;
			}
		}
		off += elen;
	}
	return off == left ? handled : -1;
}

#ifdef KS_TEST
int ks_mtk_test_wireless(struct ks_state *s, int ifindex, const uint8_t *buf, size_t len)
{
	if (!s || (!buf && len)) return -1;
	return wireless_events(s, ifindex, buf, len);
}

int ks_mtk_test_last_rrb(uint8_t *buf, size_t cap, size_t *len)
{
	if (!buf || !len || test_rrb_len > cap) return -1;
	memcpy(buf, test_rrb, test_rrb_len); *len = test_rrb_len; return 0;
}

int ks_mtk_test_last_ioctl(uint16_t *oid, int *bss, uint8_t *buf,
			   size_t cap, size_t *len)
{
	if (!oid || !bss || !buf || !len || test_ioctl_len > cap) return -1;
	*oid = test_oid; *bss = test_bss;
	memcpy(buf, test_ioctl, test_ioctl_len); *len = test_ioctl_len; return 0;
}

void ks_mtk_test_reset(void)
{
	ks_secure_clear(test_rrb, sizeof(test_rrb));
	ks_secure_clear(test_ioctl, sizeof(test_ioctl));
	test_rrb_len = test_ioctl_len = 0;
	test_rrb_count = test_ioctl_count = 0;
}

void ks_mtk_test_counts(unsigned int *rrb, unsigned int *ioctl)
{
	if (rrb) *rrb = test_rrb_count;
	if (ioctl) *ioctl = test_ioctl_count;
}

int ks_mtk_test_packet(struct ks_state *s, const uint8_t *buf, size_t len,
		       int ifindex)
{
	if (!s || !buf) return -1;
	return handle_packet(s, buf, len, ifindex);
}
#endif

int ks_backend_handle_netlink(struct ks_state *s)
{
	uint8_t buf[16384]; ssize_t n; struct nlmsghdr *nh;
	n = recv(s->netlink_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
	for (nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		struct ifinfomsg *ifi; struct rtattr *rta; int rem, bss = -1;
		bool wireless = false;
		size_t i;
		if ((nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK) ||
		    nh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi))) continue;
		ifi = NLMSG_DATA(nh); rem = IFLA_PAYLOAD(nh);
		for (i = 0; i < s->cfg.n_bss; i++)
			if (s->cfg.bss[i].ifindex == ifi->ifi_index) { bss = (int) i; break; }
		if (nh->nlmsg_type == RTM_DELLINK) {
			if (bss >= 0) {
				s->cfg.bss[bss].active = s->cfg.bss[bss].mtk_kdp = false;
				for (i = 0; i < KS_MAX_STA; i++)
					if (s->stations[i].used && s->stations[i].connected &&
					    s->stations[i].bss_index == bss) {
						s->stations[i].connected = false;
						s->stations[i].connected_ms = ks_now_ms();
					}
				for (i = 0; i < KS_MAX_KDP_PENDING; i++)
					if (s->kdp_pending[i].used && s->kdp_pending[i].source_bss == bss)
						ks_secure_clear(&s->kdp_pending[i], sizeof(s->kdp_pending[i]));
				for (i = 0; i < KS_MAX_RRB_PENDING; i++)
					if (s->pull_pending[i].used && s->pull_pending[i].target_bss == bss)
						ks_secure_clear(&s->pull_pending[i], sizeof(s->pull_pending[i]));
			}
			continue;
		}
		for (rta = IFLA_RTA(ifi); RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) if (rta->rta_type == IFLA_WIRELESS) {
			wireless = true;
			wireless_events(s, ifi->ifi_index, RTA_DATA(rta), RTA_PAYLOAD(rta));
		}
		if (!wireless && (bss >= 0 || ifi->ifi_index == s->transport_ifindex))
			(void) ks_topology_discover(s);
	}
	return 1;
}

#define KDP_STA       0x07
#define KDP_R0KH_ID   0x10
#define KDP_R0KH_LEN  0x40
#define KDP_PMKR0NAME 0x41
#define KDP_R1KH      0x51
#define KDP_S1KH      0x57
#define KDP_PMKR1NAME 0x61
#define KDP_PMK_R1    0x71
#define KDP_R0KH_MAC  0x91
#define KDP_PAIRWISE  0x97
#define KDP_AKM       0x9b
#define KDP_LIFETIME  0x9f
#define KDP_REASSOC   0xa3

static const uint8_t ccmp[4] = { 0x00, 0x0f, 0xac, 0x04 };
static const uint8_t ft_sae[4] = { 0x00, 0x0f, 0xac, 0x09 };

static bool all_zero(const uint8_t *p, size_t len)
{
	uint8_t v = 0;
	while (len--) v |= *p++;
	return v == 0;
}

static int kdp_request_base(const uint8_t *buf, size_t len, bool require_r0)
{
	uint8_t r0n;
	if (!buf || len != KS_KDP_ELEMENT_LEN ||
	    memcmp(buf, "\xff\xff\x00\xa3\x00\x0e\x2e", 7) ||
	    !ks_mac_unicast(buf + KDP_STA)) return -1;
	r0n = buf[KDP_R0KH_LEN];
	if (r0n > KS_MAX_R0KH_ID || (require_r0 && !r0n) ||
	    (r0n && all_zero(buf + KDP_R0KH_ID, r0n))) return -1;
	return 0;
}

int ks_kdp_parse_element(const uint8_t *buf, size_t len, struct ks_kdp_element *out)
{
	if (!out || kdp_request_base(buf, len, true) ||
	    !ks_mac_unicast(buf + KDP_R1KH) || !ks_mac_unicast(buf + KDP_S1KH) ||
	    !ks_mac_equal(buf + KDP_STA, buf + KDP_S1KH) ||
	    !ks_mac_unicast(buf + KDP_R0KH_MAC))
		return -1;
	memcpy(out->raw, buf, len);
	return 0;
}

int ks_kdp_parse_signal50(const uint8_t *frame, size_t len, int ifindex,
			  struct ks_kdp_element *out, uint8_t sta[6])
{
	uint32_t plen;
	(void) ifindex;
	if (!frame || len < 61 || !out || !sta || frame[12] != 0xee || frame[13] != 0xee ||
	    frame[0x20] != 0x50) return -1;
	plen = ks_get_be32(frame + 0x2a);
	if (plen != 11 || 0x32u + plen > len || !ks_mac_unicast(frame + 0x34)) return -1;
	memset(out, 0, sizeof(*out));
	memcpy(out->raw, "\xff\xff\x00\xa3\x00\x0e\x2e", 7);
	memcpy(out->raw + KDP_STA, frame + 0x34, 6);
	memcpy(out->raw + KDP_S1KH, frame + 0x34, 6);
	memcpy(sta, frame + 0x34, 6);
	return 0;
}

int ks_kdp_parse_signala1(const uint8_t *frame, size_t len, uint32_t *correlation,
			  struct ks_kdp_element *out)
{
	if (!frame || len < 217 || frame[12] != 0xee || frame[13] != 0xee ||
	    frame[0x20] != 0xa1 || ks_get_be32(frame + 0x2a) != KS_KDP_ELEMENT_LEN)
		return -1;
	if (correlation) memcpy(correlation, frame + 0x2e, 4);
	return ks_kdp_parse_element(frame + 0x32, KS_KDP_ELEMENT_LEN, out);
}

int ks_kdp_parse_signala0(const uint8_t *frame, size_t len,
			  struct ks_kdp_element *out)
{
	if (!frame || len < 217 || frame[12] != 0xee || frame[13] != 0xee ||
	    frame[0x20] != 0xa0 || ks_get_be32(frame + 0x2a) != KS_KDP_ELEMENT_LEN)
		return -1;
	frame += 0x32;
	if (!out ||
	    !ks_mac_unicast(frame + KDP_STA) ||
	    !ks_mac_unicast(frame + KDP_R1KH) ||
	    !ks_mac_equal(frame + KDP_STA, frame + KDP_S1KH) ||
	    all_zero(frame + KDP_PMKR0NAME, 16) ||
	    frame[KDP_R0KH_LEN] > KS_MAX_R0KH_ID ||
	    (frame[KDP_R0KH_LEN] &&
	     all_zero(frame + KDP_R0KH_ID, frame[KDP_R0KH_LEN])))
		return -1;
	memcpy(out->raw, frame, KS_KDP_ELEMENT_LEN);
	return 0;
}

int ks_kdp_build_wrapper(uint32_t correlation, const struct ks_kdp_element *element,
			 uint8_t out[KS_KDP_WRAPPER_LEN])
{
	if (!correlation || !element || !out) return -1;
	memset(out, 0, KS_KDP_WRAPPER_LEN);
	memcpy(out, &correlation, 4);
	memcpy(out + 12, element->raw, KS_KDP_ELEMENT_LEN);
	return 0;
}

static struct ks_kdp_pending *pending_new(struct ks_state *s)
{
	size_t i;
	for (i = 0; i < KS_MAX_KDP_PENDING; i++)
		if (!s->kdp_pending[i].used) {
			memset(&s->kdp_pending[i], 0, sizeof(s->kdp_pending[i]));
			s->kdp_pending[i].used = true;
			return &s->kdp_pending[i];
		}
	return NULL;
}

static bool pending_same(const struct ks_kdp_pending *p, int source_bss,
			 int peer_index, const uint8_t sta[6],
			 const uint8_t target_r1kh[6])
{
	return p->used && p->source_bss == source_bss &&
		p->peer_index == peer_index && ks_mac_equal(p->sta, sta) &&
		ks_mac_equal(p->target_r1kh, target_r1kh);
}

static int pending_miss(struct ks_state *s, struct ks_kdp_pending *p)
{
	struct ks_kdp_pending q;
	int rc;

	if (!p->rrb_pull) { ks_secure_clear(p, sizeof(*p)); return -1; }
	memcpy(&q, p, sizeof(q)); ks_secure_clear(p, sizeof(*p));
	rc = ks_rrb_send_resp(s, q.peer_index, q.source_bss, q.nonce, q.sta, NULL);
	ks_secure_clear(&q, sizeof(q));
	return rc;
}

int ks_kdp_pull_request(struct ks_state *s, int source_bss, int peer_index,
			const uint8_t nonce[16], const uint8_t sta[6],
			const uint8_t pmkr0name[16])
{
	struct ks_kdp_pending *p;
	struct ks_kdp_element q;
	struct ks_bss *bss;
	struct ks_ft_peer *peer;
	size_t i;

	if (!s || !nonce || !sta || !pmkr0name || source_bss < 0 ||
	    (size_t) source_bss >= s->cfg.n_bss || peer_index < 0 ||
	    (size_t) peer_index >= s->cfg.n_ft_peers ||
	    all_zero(pmkr0name, 16)) return -1;
	bss = &s->cfg.bss[source_bss]; peer = &s->cfg.ft_peers[peer_index];
	if (!bss->active || !bss->mtk_kdp || !bss->r0kh_id_len || !peer->used)
		return -1;
	for (i = 0; i < KS_MAX_KDP_PENDING; i++) {
		p = &s->kdp_pending[i];
		if (!pending_same(p, source_bss, peer_index, sta, peer->r1kh_id)) continue;
		if (p->rrb_pull) {
			if (!memcmp(p->nonce, nonce, 16) &&
			    !memcmp(p->pmkr0name, pmkr0name, 16)) return 0;
			return ks_rrb_send_resp(s, peer_index, source_bss, nonce, sta, NULL);
		}
		ks_secure_clear(p, sizeof(*p));
	}
	p = pending_new(s);
	if (!p)
		return ks_rrb_send_resp(s, peer_index, source_bss, nonce, sta, NULL);
	memset(&q, 0, sizeof(q));
	memcpy(q.raw, "\xff\xff\x00\xa3\x00\x0e\x2e", 7);
	memcpy(q.raw + KDP_STA, sta, 6);
	memcpy(q.raw + KDP_R0KH_ID, bss->r0kh_id, bss->r0kh_id_len);
	q.raw[KDP_R0KH_LEN] = (uint8_t) bss->r0kh_id_len;
	memcpy(q.raw + KDP_PMKR0NAME, pmkr0name, 16);
	memcpy(q.raw + KDP_R1KH, peer->r1kh_id, 6);
	memcpy(q.raw + KDP_S1KH, sta, 6);
	p->rrb_pull = true; p->correlation = peer->peer_ip.s_addr;
	memcpy(p->nonce, nonce, 16); memcpy(p->sta, sta, 6);
	memcpy(p->pmkr0name, pmkr0name, 16);
	memcpy(p->target_r1kh, peer->r1kh_id, 6);
	p->source_bss = source_bss; p->source_ifindex = bss->ifindex;
	p->peer_index = peer_index;
	p->deadline_ms = ks_now_ms() + s->cfg.kdp_timeout_ms;
	if (ks_backend_ft_query(s, source_bss, &q, p->correlation)) {
		ks_secure_clear(p, sizeof(*p)); ks_secure_clear(&q, sizeof(q));
		return ks_rrb_send_resp(s, peer_index, source_bss, nonce, sta, NULL);
	}
	ks_secure_clear(&q, sizeof(q));
	return 0;
}

int ks_kdp_prewarm_event(struct ks_state *s, int source_bss,
			 const struct ks_kdp_element *event)
{
	size_t i, j;
	int submitted = 0;
	uint64_t now = ks_now_ms();

	if (!s->cfg.ft_enabled || !s->rrb_key_loaded || source_bss < 0 ||
	    (size_t) source_bss >= s->cfg.n_bss || !s->cfg.bss[source_bss].mtk_kdp ||
	    !event) return 0;
	for (i = 0; i < s->cfg.n_ft_peers; i++) {
		struct ks_ft_peer *peer = &s->cfg.ft_peers[i];
		struct ks_kdp_pending *p;
		struct ks_kdp_element q;
		bool blocked = false;

		if (!peer->used || !ks_mac_unicast(peer->r1kh_id) ||
		    ks_mac_equal(peer->bssid, s->cfg.bss[source_bss].bssid) ||
		    (peer->learned && peer->ssid[0] &&
		     strcmp(peer->ssid, s->cfg.bss[source_bss].ssid))) continue;
		for (j = 0; j < KS_MAX_KDP_PENDING; j++)
			if (pending_same(&s->kdp_pending[j], source_bss, (int) i,
					 event->raw + KDP_STA, peer->r1kh_id)) {
				if (s->kdp_pending[j].rrb_pull) { blocked = true; break; }
				ks_secure_clear(&s->kdp_pending[j], sizeof(s->kdp_pending[j]));
			}
		if (blocked) continue;
		p = pending_new(s);
		if (!p) break;
		memcpy(&q, event, sizeof(q));
		if (!s->cfg.bss[source_bss].r0kh_id_len) {
			ks_secure_clear(p, sizeof(*p));
			break;
		}
		memset(q.raw + KDP_R0KH_ID, 0, KS_MAX_R0KH_ID);
		memcpy(q.raw + KDP_R0KH_ID, s->cfg.bss[source_bss].r0kh_id,
		       s->cfg.bss[source_bss].r0kh_id_len);
		q.raw[KDP_R0KH_LEN] = (uint8_t) s->cfg.bss[source_bss].r0kh_id_len;
		memset(q.raw + KDP_PMKR0NAME, 0, 16);
		memcpy(q.raw + KDP_R1KH, peer->r1kh_id, 6);
		memcpy(q.raw + KDP_S1KH, event->raw + KDP_STA, 6);
		p->correlation = peer->peer_ip.s_addr;
		memcpy(p->sta, q.raw + KDP_STA, 6);
		memcpy(p->target_r1kh, peer->r1kh_id, 6);
		p->source_bss = source_bss;
		p->source_ifindex = s->cfg.bss[source_bss].ifindex;
		p->peer_index = (int) i;
		p->deadline_ms = now + s->cfg.kdp_timeout_ms;
		if (ks_backend_ft_query(s, source_bss, &q, p->correlation)) {
			ks_secure_clear(p, sizeof(*p));
			continue;
		}
		submitted++;
	}
	return submitted;
}

int ks_kdp_handle_response(struct ks_state *s, int ifindex, uint32_t correlation,
			   const struct ks_kdp_element *response)
{
	size_t i;
	uint64_t now = ks_now_ms();

	for (i = 0; i < KS_MAX_KDP_PENDING; i++) {
		struct ks_kdp_pending *p = &s->kdp_pending[i];
		const uint8_t *e = response->raw;
		struct ks_kdp_pending q;
		int peer, rc;

		if (!p->used || p->correlation != correlation || p->source_ifindex != ifindex ||
		    now > p->deadline_ms || !ks_mac_equal(p->sta, e + KDP_STA) ||
		    !ks_mac_equal(p->sta, e + KDP_S1KH) ||
		    !ks_mac_equal(p->target_r1kh, e + KDP_R1KH)) continue;
		if (p->rrb_pull && memcmp(p->pmkr0name, e + KDP_PMKR0NAME, 16))
			continue;
		peer = p->peer_index;
		if (p->source_bss < 0 || (size_t) p->source_bss >= s->cfg.n_bss ||
		    e[KDP_R0KH_LEN] != s->cfg.bss[p->source_bss].r0kh_id_len ||
		    memcmp(e + KDP_R0KH_ID, s->cfg.bss[p->source_bss].r0kh_id,
			   e[KDP_R0KH_LEN]) ||
		    !ks_mac_equal(e + KDP_R0KH_MAC, s->cfg.bss[p->source_bss].bssid)) {
			return pending_miss(s, p);
		}
		if (!memcmp(e + KDP_PMKR0NAME, (uint8_t[16]) {0}, 16) ||
		    !memcmp(e + KDP_PMKR1NAME, (uint8_t[16]) {0}, 16) ||
		    !memcmp(e + KDP_PMK_R1, (uint8_t[32]) {0}, 32) ||
		    memcmp(e + KDP_PAIRWISE, ccmp, 4) || memcmp(e + KDP_AKM, ft_sae, 4) ||
		    !ks_get_le32(e + KDP_LIFETIME)) return pending_miss(s, p);
		memcpy(&q, p, sizeof(q)); ks_secure_clear(p, sizeof(*p));
		rc = q.rrb_pull ?
			ks_rrb_send_resp(s, peer, q.source_bss, q.nonce, q.sta, response) :
			ks_rrb_send_push(s, peer, response);
		ks_secure_clear(&q, sizeof(q));
		return rc;
	}
	return 0;
}

void ks_kdp_expire(struct ks_state *s, uint64_t now)
{
	size_t i;
	for (i = 0; i < KS_MAX_KDP_PENDING; i++)
		if (s->kdp_pending[i].used && now >= s->kdp_pending[i].deadline_ms) {
			if (s->kdp_pending[i].rrb_pull)
				(void) pending_miss(s, &s->kdp_pending[i]);
			else
				ks_secure_clear(&s->kdp_pending[i], sizeof(s->kdp_pending[i]));
		}
}

const uint8_t *ks_kdp_sta(const struct ks_kdp_element *e) { return e->raw + KDP_STA; }
const uint8_t *ks_kdp_r0kh_id(const struct ks_kdp_element *e, size_t *len) { *len = e->raw[KDP_R0KH_LEN]; return e->raw + KDP_R0KH_ID; }
const uint8_t *ks_kdp_pmkr0name(const struct ks_kdp_element *e) { return e->raw + KDP_PMKR0NAME; }
const uint8_t *ks_kdp_r1kh(const struct ks_kdp_element *e) { return e->raw + KDP_R1KH; }
const uint8_t *ks_kdp_pmkr1name(const struct ks_kdp_element *e) { return e->raw + KDP_PMKR1NAME; }
const uint8_t *ks_kdp_pmkr1(const struct ks_kdp_element *e) { return e->raw + KDP_PMK_R1; }
const uint8_t *ks_kdp_r0kh_mac(const struct ks_kdp_element *e) { return e->raw + KDP_R0KH_MAC; }
uint32_t ks_kdp_lifetime(const struct ks_kdp_element *e) { return ks_get_le32(e->raw + KDP_LIFETIME); }

int ks_kdp_from_rrb(struct ks_kdp_element *e, const uint8_t sta[6],
		    const uint8_t *r0kh_id, size_t r0kh_len,
		    const uint8_t pmkr0name[16], const uint8_t target_r1kh[6],
		    const uint8_t pmkr1name[16], const uint8_t pmkr1[32],
		    const uint8_t r0kh_mac[6], uint16_t pairwise,
		    uint32_t expires)
{
	if (!e || !sta || !ks_mac_unicast(sta) || !r0kh_id || !r0kh_len ||
	    r0kh_len > KS_MAX_R0KH_ID || !target_r1kh || !ks_mac_unicast(target_r1kh) ||
	    !pmkr0name || !pmkr1name || !pmkr1 || !r0kh_mac ||
	    !ks_mac_unicast(r0kh_mac) || pairwise != 0x10 || !expires ||
	    !memcmp(pmkr0name, (uint8_t[16]) {0}, 16) ||
	    !memcmp(pmkr1name, (uint8_t[16]) {0}, 16) ||
	    !memcmp(pmkr1, (uint8_t[32]) {0}, 32)) return -1;
	memset(e, 0, sizeof(*e));
	memcpy(e->raw, "\xff\xff\x00\xa3\x00\x0e\x2e", 7);
	memcpy(e->raw + KDP_STA, sta, 6);
	memcpy(e->raw + KDP_R0KH_ID, r0kh_id, r0kh_len);
	e->raw[KDP_R0KH_LEN] = (uint8_t) r0kh_len;
	memcpy(e->raw + KDP_PMKR0NAME, pmkr0name, 16);
	memcpy(e->raw + KDP_R1KH, target_r1kh, 6);
	memcpy(e->raw + KDP_S1KH, sta, 6);
	memcpy(e->raw + KDP_PMKR1NAME, pmkr1name, 16);
	memcpy(e->raw + KDP_PMK_R1, pmkr1, 32);
	memcpy(e->raw + KDP_R0KH_MAC, r0kh_mac, 6);
	memcpy(e->raw + KDP_PAIRWISE, ccmp, 4);
	memcpy(e->raw + KDP_AKM, ft_sae, 4);
	ks_put_le32(e->raw + KDP_LIFETIME, expires);
	ks_put_le32(e->raw + KDP_REASSOC, 20);
	return 0;
}
