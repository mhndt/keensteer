#ifndef KEENSTEER_H
#define KEENSTEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>

#define KS_VERSION "1.0.3"

#define KS_MAX_BSS             8
#define KS_MAX_STA           256
#define KS_MAX_USTEER_PEERS   16
#define KS_MAX_FT_PEERS       16
#define KS_MAX_KDP_PENDING    32
#define KS_MAX_RRB_PENDING    32
#define KS_MAX_R0KH_ID        48
#define KS_MAX_SSID           32
#define KS_MAX_NODE_NAME      63
#define KS_MAX_PACKET      65535
#define KS_MAX_RRB_BODY     2048
#define KS_MAX_CONFIG_LINE  512

#define KS_ETH_P_RRB      0x88b7
#define KS_ETH_P_MTK_KDP  0xeeee
#define KS_MTK_PRIV_IOCTL 0x8be1
#define KS_MTK_LOAD_IOCTL 0x8bea
#define KS_MTK_MAC_TABLE_IOCTL 0x8bef
#define KS_OID_FT_QUERY   0x8409
#define KS_OID_FT_INSERT  0x840a
#define KS_OID_FT_NEIGHBOR 0x840e

#define KS_KDP_ELEMENT_LEN 167
#define KS_KDP_WRAPPER_LEN 179

enum ks_log_level {
	KS_LOG_ERROR = 0,
	KS_LOG_WARN,
	KS_LOG_INFO,
	KS_LOG_DEBUG,
};

enum ks_band {
	KS_BAND_UNKNOWN = 0,
	KS_BAND_2GHZ = 2,
	KS_BAND_5GHZ = 5,
};

struct ks_bss {
	bool active;
	bool mtk_kdp;
	char ifname[IFNAMSIZ];
	char name[KS_MAX_NODE_NAME + 1];
	char ssid[KS_MAX_SSID + 1];
	uint8_t bssid[6];
	uint8_t r1kh_id[6];
	char r0kh_id[KS_MAX_R0KH_ID + 1];
	size_t r0kh_id_len;
	int ifindex;
	int freq;
	int channel;
	int op_class;
	int noise;
	int load;
	int max_assoc;
	enum ks_band band;
};

struct ks_station {
	bool used;
	uint8_t addr[6];
	int bss_index;
	int signal[KS_MAX_BSS];
	bool connected;
	bool seen_2ghz;
	bool seen_5ghz;
	uint64_t seen_ms[KS_MAX_BSS];
	uint64_t connected_ms;
};

struct ks_usteer_peer {
	bool used;
	struct sockaddr_in addr;
};

struct ks_ft_peer {
	bool used;
	bool learned;
	bool static_config;
	bool sink_ready;
	int neighbor_channel;
	int neighbor_op_class;
	struct in_addr peer_ip;
	uint8_t transport[6];
	uint8_t r1kh_id[6];
	char r0kh_id[KS_MAX_R0KH_ID + 1];
	size_t r0kh_id_len;
	uint8_t bssid[6];
	char ssid[KS_MAX_SSID + 1];
	int channel;
	int op_class;
	uint64_t last_seen_ms;

	uint32_t tx_domain;
	uint32_t tx_seq;
	uint32_t rx_domain;
	uint32_t rx_last[16];
	unsigned int rx_count;
	unsigned int rx_offset;
	int64_t rx_clock_offset;
};

struct ks_config {
	char path[256];
	char transport_if[IFNAMSIZ];
	bool usteer_enabled;
	bool ft_enabled;
	bool debug;
	unsigned int usteer_interval_ms;
	unsigned int station_ttl_ms;
	unsigned int peer_ttl_ms;
	unsigned int kdp_timeout_ms;
	char rrb_key_file[256];
	struct ks_usteer_peer usteer_peers[KS_MAX_USTEER_PEERS];
	size_t n_usteer_peers;
	struct ks_ft_peer ft_peers[KS_MAX_FT_PEERS];
	size_t n_ft_peers;
	struct ks_bss bss[KS_MAX_BSS];
	size_t n_bss;
};

struct ks_kdp_element {
	uint8_t raw[KS_KDP_ELEMENT_LEN];
};

struct ks_kdp_pending {
	bool used;
	bool rrb_pull;
	uint32_t correlation;
	uint8_t nonce[16];
	uint8_t sta[6];
	uint8_t pmkr0name[16];
	uint8_t target_r1kh[6];
	int source_bss;
	int source_ifindex;
	int peer_index;
	uint64_t deadline_ms;
};

struct ks_rrb_pending {
	bool used;
	uint8_t source[6];
	uint8_t subtype;
	uint8_t nonce[16];
	uint8_t frame[KS_MAX_RRB_BODY + 20];
	size_t frame_len;
	uint64_t deadline_ms;
};

struct ks_pull_pending {
	bool used;
	uint8_t nonce[16];
	uint8_t sta[6];
	uint8_t pmkr0name[16];
	int peer_index;
	int target_bss;
	uint64_t deadline_ms;
};

struct ks_state {
	struct ks_config cfg;
	struct ks_station stations[KS_MAX_STA];
	struct ks_kdp_pending kdp_pending[KS_MAX_KDP_PENDING];
	struct ks_rrb_pending rrb_pending[KS_MAX_RRB_PENDING];
	struct ks_pull_pending pull_pending[KS_MAX_RRB_PENDING];
	uint8_t rrb_key[32];
	bool rrb_key_loaded;
	uint32_t usteer_id;
	uint32_t usteer_seq;
	int udp_fd;
	int packet_fd;
	int netlink_fd;
	int ioctl_fd;
	int transport_ifindex;
	uint8_t transport_mac[6];
	uint64_t next_usteer_ms;
	uint64_t next_load_ms;
	uint64_t next_sink_probe_ms;
	uint64_t next_reconcile_ms;
	unsigned int sink_probe_cursor;
	bool reconcile_off;
	bool neighbor_off;
	bool stop;
};

struct ks_rrb_message {
	uint8_t subtype;
	uint8_t src[6];
	uint8_t dst[6];
	const uint8_t *auth;
	size_t auth_len;
	const uint8_t *encrypted;
	size_t encrypted_len;
};

struct ks_rrb_plain {
	uint8_t data[KS_MAX_RRB_BODY];
	size_t len;
};

extern enum ks_log_level ks_log_threshold;

void ks_log(enum ks_log_level level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
uint64_t ks_now_ms(void);
void ks_secure_clear(void *p, size_t len);
bool ks_mac_parse(const char *s, uint8_t mac[6]);
void ks_mac_format(const uint8_t mac[6], char out[18]);
bool ks_mac_equal(const uint8_t a[6], const uint8_t b[6]);
bool ks_mac_unicast(const uint8_t mac[6]);
uint16_t ks_get_le16(const void *p);
uint32_t ks_get_le32(const void *p);
void ks_put_le16(void *p, uint16_t v);
void ks_put_le32(void *p, uint32_t v);
uint32_t ks_get_be32(const void *p);
void ks_put_be32(void *p, uint32_t v);
int ks_random(void *buf, size_t len);

void ks_config_defaults(struct ks_config *cfg);
int ks_config_load(struct ks_config *cfg, const char *path, char *err,
		   size_t err_len);
int ks_load_rrb_key(const char *path, uint8_t key[32], char *err,
		    size_t err_len);

int ks_topology_discover(struct ks_state *s);
struct ks_station *ks_station_get(struct ks_state *s, const uint8_t addr[6],
				  bool create);
void ks_station_expire(struct ks_state *s, uint64_t now);
int ks_bss_by_ifindex(const struct ks_state *s, int ifindex);
int ks_bss_by_bssid(const struct ks_state *s, const uint8_t bssid[6]);
int ks_bss_by_r1kh(const struct ks_state *s, const uint8_t r1kh[6]);

int ks_usteer_encode(const struct ks_state *s, uint8_t *out, size_t cap,
		     size_t *out_len);
int ks_usteer_send(struct ks_state *s);
int ks_usteer_receive(struct ks_state *s);
int ks_usteer_parse(struct ks_state *s, const uint8_t *buf, size_t len,
		    const struct sockaddr_in *src, uint64_t now);
void ks_usteer_expire(struct ks_state *s, uint64_t now);

int ks_backend_open(struct ks_state *s);
void ks_backend_close(struct ks_state *s);
void ks_backend_reprobe(struct ks_state *s, uint64_t now);
int ks_backend_reconcile(struct ks_state *s, uint64_t now);
void ks_backend_update_load(struct ks_state *s);
int ks_backend_handle_packet(struct ks_state *s);
int ks_backend_handle_netlink(struct ks_state *s);
int ks_backend_ft_query(struct ks_state *s, int bss_index,
			const struct ks_kdp_element *element,
			uint32_t correlation);
int ks_backend_ft_insert(struct ks_state *s, int bss_index,
			 struct in_addr source,
			 const struct ks_kdp_element *element);
int ks_backend_neighbor(struct ks_state *s, int peer_index, int channel, int op_class,
			bool present);
int ks_backend_send_rrb(struct ks_state *s, const uint8_t dst[6],
			const uint8_t *frame, size_t len);
#ifdef KS_TEST
int ks_mtk_test_bndstrg(const uint8_t *buf, size_t len, uint8_t mac[6],
			int *signal);
int ks_mtk_test_wireless(struct ks_state *s, int ifindex,
			 const uint8_t *buf, size_t len);
int ks_mtk_test_last_rrb(uint8_t *buf, size_t cap, size_t *len);
int ks_mtk_test_last_ioctl(uint16_t *oid, int *bss, uint8_t *buf,
			   size_t cap, size_t *len);
void ks_mtk_test_reset(void);
void ks_mtk_test_counts(unsigned int *rrb, unsigned int *ioctl);
int ks_mtk_test_packet(struct ks_state *s, const uint8_t *buf, size_t len,
		       int ifindex);
#endif

int ks_kdp_parse_element(const uint8_t *buf, size_t len,
			 struct ks_kdp_element *out);
int ks_kdp_parse_signal50(const uint8_t *frame, size_t len, int ifindex,
			  struct ks_kdp_element *out, uint8_t sta[6]);
int ks_kdp_parse_signala1(const uint8_t *frame, size_t len,
			  uint32_t *correlation,
			  struct ks_kdp_element *out);
int ks_kdp_parse_signala0(const uint8_t *frame, size_t len,
			  struct ks_kdp_element *out);
int ks_kdp_build_wrapper(uint32_t correlation,
			 const struct ks_kdp_element *element,
			 uint8_t out[KS_KDP_WRAPPER_LEN]);
int ks_kdp_prewarm_event(struct ks_state *s, int source_bss,
			 const struct ks_kdp_element *event);
int ks_kdp_pull_request(struct ks_state *s, int source_bss, int peer_index,
			const uint8_t nonce[16], const uint8_t sta[6],
			const uint8_t pmkr0name[16]);
int ks_kdp_handle_response(struct ks_state *s, int ifindex,
			   uint32_t correlation,
			   const struct ks_kdp_element *response);
void ks_kdp_expire(struct ks_state *s, uint64_t now);
const uint8_t *ks_kdp_sta(const struct ks_kdp_element *e);
const uint8_t *ks_kdp_r0kh_id(const struct ks_kdp_element *e, size_t *len);
const uint8_t *ks_kdp_pmkr0name(const struct ks_kdp_element *e);
const uint8_t *ks_kdp_r1kh(const struct ks_kdp_element *e);
const uint8_t *ks_kdp_pmkr1name(const struct ks_kdp_element *e);
const uint8_t *ks_kdp_pmkr1(const struct ks_kdp_element *e);
const uint8_t *ks_kdp_r0kh_mac(const struct ks_kdp_element *e);
uint32_t ks_kdp_lifetime(const struct ks_kdp_element *e);
int ks_kdp_from_rrb(struct ks_kdp_element *e, const uint8_t sta[6],
		    const uint8_t *r0kh_id, size_t r0kh_len,
		    const uint8_t pmkr0name[16], const uint8_t target_r1kh[6],
		    const uint8_t pmkr1name[16], const uint8_t pmkr1[32],
		    const uint8_t r0kh_mac[6], uint16_t pairwise,
		    uint32_t expires);

int ks_rrb_expand_key(const uint8_t old_key[16], uint8_t out[32]);
int ks_aes_siv_encrypt(const uint8_t key[32], const uint8_t *plain,
		       size_t plain_len, const uint8_t *const ad[],
		       const size_t ad_len[], size_t n_ad, uint8_t *out);
int ks_aes_siv_decrypt(const uint8_t key[32], const uint8_t *in,
		       size_t in_len, const uint8_t *const ad[],
		       const size_t ad_len[], size_t n_ad, uint8_t *out);
int ks_rrb_parse_frame(const uint8_t *frame, size_t len,
		       struct ks_rrb_message *out);
int ks_rrb_decrypt(const uint8_t key[32], const struct ks_rrb_message *msg,
		   struct ks_rrb_plain *plain);
int ks_rrb_build(uint8_t subtype, const uint8_t src[6], const uint8_t dst[6],
		 const uint8_t key[32], const uint8_t *auth, size_t auth_len,
		 const uint8_t *plain, size_t plain_len, uint8_t *out,
		 size_t cap, size_t *out_len);
int ks_rrb_handle_frame(struct ks_state *s, const uint8_t *frame, size_t len);
int ks_rrb_send_push(struct ks_state *s, int peer_index,
		     const struct ks_kdp_element *element);
int ks_rrb_send_pull(struct ks_state *s, int target_bss,
		     const struct ks_kdp_element *element);
int ks_rrb_send_resp(struct ks_state *s, int peer_index, int source_bss,
		     const uint8_t nonce[16], const uint8_t sta[6],
		     const struct ks_kdp_element *element);
void ks_rrb_expire(struct ks_state *s, uint64_t now);

#endif
