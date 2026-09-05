#define _GNU_SOURCE
#include "keensteer.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

enum ks_log_level ks_log_threshold = KS_LOG_INFO;

void ks_log(enum ks_log_level level, const char *fmt, ...)
{
	static const int priorities[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG };
	va_list ap;

	if (level > ks_log_threshold)
		return;
	va_start(ap, fmt);
	vsyslog(priorities[level], fmt, ap);
	va_end(ap);
}

uint64_t ks_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

void ks_secure_clear(void *p, size_t len)
{
	volatile unsigned char *q = p;

	while (len--)
		*q++ = 0;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

bool ks_mac_parse(const char *s, uint8_t mac[6])
{
	unsigned int i;

	if (!s)
		return false;
	for (i = 0; i < 6; i++) {
		int hi = hexval((unsigned char) s[0]);
		int lo = hexval((unsigned char) s[1]);
		if (hi < 0 || lo < 0)
			return false;
		mac[i] = (uint8_t) ((hi << 4) | lo);
		s += 2;
		if (i != 5) {
			if (*s++ != ':')
				return false;
		} else if (*s != '\0') {
			return false;
		}
	}
	return ks_mac_unicast(mac);
}

void ks_mac_format(const uint8_t mac[6], char out[18])
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool ks_mac_equal(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

bool ks_mac_unicast(const uint8_t mac[6])
{
	static const uint8_t zero[6];
	return !(mac[0] & 1) && memcmp(mac, zero, 6) != 0;
}

uint16_t ks_get_le16(const void *p)
{
	const uint8_t *q = p;
	return (uint16_t) q[0] | ((uint16_t) q[1] << 8);
}

uint32_t ks_get_le32(const void *p)
{
	const uint8_t *q = p;
	return (uint32_t) q[0] | ((uint32_t) q[1] << 8) |
	       ((uint32_t) q[2] << 16) | ((uint32_t) q[3] << 24);
}

void ks_put_le16(void *p, uint16_t v)
{
	uint8_t *q = p;
	q[0] = (uint8_t) v;
	q[1] = (uint8_t) (v >> 8);
}

void ks_put_le32(void *p, uint32_t v)
{
	uint8_t *q = p;
	q[0] = (uint8_t) v;
	q[1] = (uint8_t) (v >> 8);
	q[2] = (uint8_t) (v >> 16);
	q[3] = (uint8_t) (v >> 24);
}

uint32_t ks_get_be32(const void *p)
{
	const uint8_t *q = p;
	return ((uint32_t) q[0] << 24) | ((uint32_t) q[1] << 16) |
	       ((uint32_t) q[2] << 8) | (uint32_t) q[3];
}

void ks_put_be32(void *p, uint32_t v)
{
	uint8_t *q = p;
	q[0] = (uint8_t) (v >> 24);
	q[1] = (uint8_t) (v >> 16);
	q[2] = (uint8_t) (v >> 8);
	q[3] = (uint8_t) v;
}

int ks_random(void *buf, size_t len)
{
	uint8_t *p = buf;
	int fd;

#ifdef GRND_NONBLOCK
	ssize_t got = getrandom(p, len, 0);
	if (got == (ssize_t) len)
		return 0;
#endif
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (len) {
		ssize_t n = read(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			return -1;
		}
		p += n;
		len -= (size_t) n;
	}
	close(fd);
	return 0;
}

#ifndef KS_TEST
static volatile sig_atomic_t stopped;

static void stop_handler(int signo)
{
	(void) signo;
	stopped = 1;
}

static int install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stop_handler;
	sigemptyset(&sa.sa_mask);
	return sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL) ? -1 : 0;
}

static int drain(struct ks_state *s, int (*fn)(struct ks_state *))
{
	int rc;

	do rc = fn(s); while (rc > 0);
	return rc;
}

#define DISCOVER_RETRY_MS 60000

static int run(struct ks_state *s)
{
	uint64_t next_expire = ks_now_ms(), next_discover = next_expire + DISCOVER_RETRY_MS;

	while (!stopped) {
		struct pollfd pfd[3];
		uint64_t now, next;
		nfds_t n = 0;
		int timeout, rc;

		now = ks_now_ms();
		if (now >= next_expire) {
			ks_station_expire(s, now);
			ks_usteer_expire(s, now);
			ks_kdp_expire(s, now);
			ks_rrb_expire(s, now);
			ks_backend_reprobe(s, now);
			(void) ks_backend_reconcile(s, now);
			next_expire = now + 1000;
		}
		if (now >= next_discover) {
			if (ks_active_bss(s) < s->cfg.n_bss) (void) ks_topology_discover(s);
			next_discover = now + DISCOVER_RETRY_MS;
		}
		if (s->cfg.usteer_enabled && now >= s->next_usteer_ms) {
			if (ks_usteer_send(s))
				ks_log(KS_LOG_DEBUG, "usteer update failed");
			s->next_usteer_ms = now + s->cfg.usteer_interval_ms;
		}

		if (s->packet_fd >= 0) pfd[n++] = (struct pollfd) { s->packet_fd, POLLIN, 0 };
		if (s->netlink_fd >= 0) pfd[n++] = (struct pollfd) { s->netlink_fd, POLLIN, 0 };
		if (s->udp_fd >= 0) pfd[n++] = (struct pollfd) { s->udp_fd, POLLIN, 0 };
		next = next_expire;
		if (s->cfg.usteer_enabled && s->next_usteer_ms < next)
			next = s->next_usteer_ms;
		now = ks_now_ms();
		timeout = next <= now ? 0 : (next - now > INT32_MAX ? INT32_MAX : (int) (next - now));
		rc = poll(pfd, n, timeout);
		if (rc < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		for (nfds_t i = 0; i < n && rc > 0; i++) {
			int io_rc = 0;
			if (!(pfd[i].revents & (POLLIN | POLLERR | POLLHUP))) continue;
			rc--;
			if (pfd[i].fd == s->packet_fd) io_rc = drain(s, ks_backend_handle_packet);
			else if (pfd[i].fd == s->netlink_fd) io_rc = drain(s, ks_backend_handle_netlink);
			else if (pfd[i].fd == s->udp_fd) io_rc = drain(s, ks_usteer_receive);
			if (io_rc < 0) return -1;
		}
	}
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f, "usage: keensteerd [-d] [-c file]\n");
}

int main(int argc, char **argv)
{
	struct ks_state s;
	struct rlimit core = { 0, 0 };
	const char *path = "/opt/etc/keensteer.conf";
	char err[256];
	bool debug = false;
	int ch, rc = 1;

	memset(&s, 0, sizeof(s));
	s.udp_fd = s.packet_fd = s.netlink_fd = s.ioctl_fd = -1;
	ks_config_defaults(&s.cfg);
	while ((ch = getopt(argc, argv, "c:dhV")) != -1) {
		switch (ch) {
		case 'c': path = optarg; break;
		case 'd': debug = true; break;
		case 'V': printf("keensteerd %s\n", KS_VERSION); return 0;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}
	openlog("keensteerd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (ks_config_load(&s.cfg, path, err, sizeof(err))) {
		ks_log(KS_LOG_ERROR, "%s", err);
		goto out;
	}
	if (debug) s.cfg.debug = true;
	ks_log_threshold = s.cfg.debug ? KS_LOG_DEBUG : KS_LOG_INFO;
	if (!s.cfg.usteer_enabled && !s.cfg.ft_enabled) {
		ks_log(KS_LOG_ERROR, "no subsystem enabled");
		goto out;
	}
	if (ks_topology_discover(&s) && !s.transport_ifindex) {
		ks_log(KS_LOG_ERROR, "interface %s not found", s.cfg.transport_if);
		goto out;
	}
	if (!ks_active_bss(&s))
		ks_log(KS_LOG_WARN, "no active access point yet, waiting");
	if (s.cfg.ft_enabled &&
	    ks_load_rrb_key(s.cfg.rrb_key_file, s.rrb_key, err, sizeof(err))) {
		ks_log(KS_LOG_WARN, "FT disabled: %s", err);
		s.cfg.ft_enabled = false;
	} else if (s.cfg.ft_enabled) {
		s.rrb_key_loaded = true;
		setrlimit(RLIMIT_CORE, &core);
		prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	}
	if (!s.cfg.usteer_enabled && !s.cfg.ft_enabled) {
		ks_log(KS_LOG_ERROR, "no usable subsystem");
		goto out;
	}
	if (ks_random(&s.usteer_id, sizeof(s.usteer_id))) {
		ks_log(KS_LOG_ERROR, "random source unavailable");
		goto out;
	}
	if (!s.usteer_id) s.usteer_id = 1;
	if (install_signals() || ks_backend_open(&s)) {
		ks_log(KS_LOG_ERROR, "backend initialization failed");
		goto out;
	}
	s.next_usteer_ms = ks_now_ms();
	ks_log(KS_LOG_INFO, "started usteer=%u ft=%u bss=%zu",
	       s.cfg.usteer_enabled, s.cfg.ft_enabled, s.cfg.n_bss);
	rc = run(&s) ? 1 : 0;
	ks_log(KS_LOG_INFO, "stopped");
out:
	ks_backend_close(&s);
	ks_secure_clear(s.kdp_pending, sizeof(s.kdp_pending));
	ks_secure_clear(s.rrb_pending, sizeof(s.rrb_pending));
	ks_secure_clear(s.pull_pending, sizeof(s.pull_pending));
	ks_secure_clear(s.rrb_key, sizeof(s.rrb_key));
	closelog();
	return rc;
}
#endif
