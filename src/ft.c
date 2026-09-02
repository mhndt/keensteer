#define _GNU_SOURCE
#include "keensteer.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/cmac.h>
#endif
#include <string.h>

#define RRB_PULL     1
#define RRB_RESP     2
#define RRB_PUSH     3
#define RRB_SEQ_REQ  4
#define RRB_SEQ_RESP 5

#define TLV_SEQ          1
#define TLV_NONCE        2
#define TLV_R0KH_ID      4
#define TLV_R1KH_ID      5
#define TLV_S1KH_ID      6
#define TLV_PMKR0_NAME   7
#define TLV_PMKR1_NAME   9
#define TLV_PMK_R1      10
#define TLV_PAIRWISE    11
#define TLV_EXPIRES_IN  12

static const uint8_t oui[] = { 0x00, 0x13, 0x74, 0x00, 0x01 };

struct rb { uint8_t *p; size_t cap, len; };

static int put(struct rb *b, const void *p, size_t n)
{
	if (n > b->cap - b->len) return -1;
	if (n) memcpy(b->p + b->len, p, n);
	b->len += n;
	return 0;
}

static int tlv(struct rb *b, uint16_t type, const void *p, size_t n)
{
	uint8_t h[4];
	if (n > UINT16_MAX) return -1;
	ks_put_le16(h, type); ks_put_le16(h + 2, (uint16_t) n);
	return put(b, h, sizeof(h)) || put(b, p, n) ? -1 : 0;
}

static int cmac_one(const uint8_t key[16], const uint8_t *p, size_t n,
		    uint8_t out[16])
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static char name128[] = "AES-128-CBC";
	EVP_MAC *mac;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t olen = 0;
	int ok;

	mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (!mac) return -1;
	ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (!ctx) return -1;
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, name128, 0);
	params[1] = OSSL_PARAM_construct_end();
	ok = EVP_MAC_init(ctx, key, 16, params) == 1 &&
	     EVP_MAC_update(ctx, p, n) == 1 &&
	     EVP_MAC_final(ctx, out, &olen, 16) == 1 && olen == 16;
	EVP_MAC_CTX_free(ctx);
	return ok ? 0 : -1;
#else
	CMAC_CTX *c = CMAC_CTX_new(); size_t olen = 0; int ok = 0;
	if (!c) return -1;
	ok = CMAC_Init(c, key, 16, EVP_aes_128_cbc(), NULL) == 1 &&
	     CMAC_Update(c, p, n) == 1 && CMAC_Final(c, out, &olen) == 1 && olen == 16;
	CMAC_CTX_free(c); return ok ? 0 : -1;
#endif
}

static void dbl(uint8_t v[16])
{
	unsigned int i, carry = v[0] >> 7;
	for (i = 0; i < 15; i++) v[i] = (uint8_t) ((v[i] << 1) | (v[i + 1] >> 7));
	v[15] <<= 1; if (carry) v[15] ^= 0x87;
}

static void xor16(uint8_t a[16], const uint8_t b[16])
{
	unsigned int i; for (i = 0; i < 16; i++) a[i] ^= b[i];
}

static int s2v(const uint8_t key[16], const uint8_t *plain, size_t plain_len,
	       const uint8_t *const ad[], const size_t ad_len[], size_t n_ad,
	       uint8_t out[16])
{
	uint8_t d[16], t[16], last[KS_MAX_RRB_BODY], zero[16] = {0};
	size_t i;
	if (plain_len > sizeof(last)) return -1;
	if (cmac_one(key, zero, sizeof(zero), d)) return -1;
	for (i = 0; i < n_ad; i++) {
		if (cmac_one(key, ad[i], ad_len[i], t)) goto bad;
		dbl(d); xor16(d, t);
	}
	if (plain_len >= 16) {
		memcpy(last, plain, plain_len);
		for (i = 0; i < 16; i++) last[plain_len - 16 + i] ^= d[i];
		if (cmac_one(key, last, plain_len, out)) goto bad;
	} else {
		memset(t, 0, sizeof(t)); if (plain_len) memcpy(t, plain, plain_len); t[plain_len] = 0x80;
		dbl(d); xor16(d, t); if (cmac_one(key, d, 16, out)) goto bad;
	}
	ks_secure_clear(last, sizeof(last));
	ks_secure_clear(d, sizeof(d)); ks_secure_clear(t, sizeof(t)); return 0;
bad:
	ks_secure_clear(last, sizeof(last));
	ks_secure_clear(d, sizeof(d)); ks_secure_clear(t, sizeof(t)); return -1;
}

static int ctr(const uint8_t key[16], const uint8_t iv0[16], uint8_t *p, size_t n)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); uint8_t iv[16]; int a = 0, z = 0, ok;
	if (!c || n > INT_MAX) { EVP_CIPHER_CTX_free(c); return -1; }
	memcpy(iv, iv0, 16); iv[8] &= 0x7f; iv[12] &= 0x7f;
	ok = EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), NULL, key, iv) == 1 &&
	     EVP_EncryptUpdate(c, p, &a, p, (int) n) == 1 &&
	     EVP_EncryptFinal_ex(c, p + a, &z) == 1 && (size_t) (a + z) == n;
	EVP_CIPHER_CTX_free(c); ks_secure_clear(iv, sizeof(iv)); return ok ? 0 : -1;
}

int ks_aes_siv_encrypt(const uint8_t key[32], const uint8_t *plain,
		       size_t plain_len,
		       const uint8_t *const ad[], const size_t ad_len[], size_t n_ad,
		       uint8_t *out)
{
	if (!key || (!plain && plain_len) || !out || n_ad > 5 ||
	    (n_ad && (!ad || !ad_len))) return -1;
	for (size_t i = 0; i < n_ad; i++) if (!ad[i] && ad_len[i]) return -1;
	if (s2v(key, plain, plain_len, ad, ad_len, n_ad, out)) return -1;
	if (plain_len) memcpy(out + 16, plain, plain_len);
	return ctr(key + 16, out, out + 16, plain_len);
}

int ks_aes_siv_decrypt(const uint8_t key[32], const uint8_t *in,
		       size_t in_len,
		       const uint8_t *const ad[], const size_t ad_len[], size_t n_ad,
		       uint8_t *out)
{
	uint8_t tag[16]; size_t n;
	if (!key || !in || in_len < 16 || !out || n_ad > 5 ||
	    (n_ad && (!ad || !ad_len))) return -1;
	for (size_t i = 0; i < n_ad; i++) if (!ad[i] && ad_len[i]) return -1;
	n = in_len - 16; if (n) memcpy(out, in + 16, n);
	if (ctr(key + 16, in, out, n) || s2v(key, out, n, ad, ad_len, n_ad, tag) ||
	    CRYPTO_memcmp(tag, in, 16)) {
		ks_secure_clear(tag, sizeof(tag)); ks_secure_clear(out, n); return -1;
	}
	ks_secure_clear(tag, sizeof(tag)); return 0;
}

int ks_rrb_expand_key(const uint8_t old_key[16], uint8_t out[32])
{
	static const uint8_t label[] = { 'F','T',' ','O','L','D','K','E','Y',0,1 };
	unsigned int n = 0;
	return HMAC(EVP_sha256(), old_key, 16, label, sizeof(label), out, &n) && n == 32 ? 0 : -1;
}

int ks_rrb_parse_frame(const uint8_t *frame, size_t len, struct ks_rrb_message *out)
{
	uint16_t alen;
	if (!frame || !out || len < 84 || len > KS_MAX_PACKET ||
	    frame[12] != 0x88 || frame[13] != 0xb7 || memcmp(frame + 14, oui, sizeof(oui)) ||
	    frame[19] < RRB_PULL || frame[19] > RRB_SEQ_RESP) return -1;
	alen = ks_get_le16(frame + 20);
	if ((size_t) alen > len - 22 || len - 22 - alen < 16 || len - 20 > KS_MAX_RRB_BODY) return -1;
	memset(out, 0, sizeof(*out)); out->subtype = frame[19];
	memcpy(out->dst, frame, 6); memcpy(out->src, frame + 6, 6);
	out->auth = frame + 22; out->auth_len = alen;
	out->encrypted = out->auth + alen; out->encrypted_len = len - 22 - alen;
	return 0;
}

int ks_rrb_decrypt(const uint8_t key[32], const struct ks_rrb_message *msg,
		   struct ks_rrb_plain *plain)
{
	const uint8_t *ad[3];
	size_t al[3];
	if (!key || !msg || !plain) return -1;
	ad[0] = msg->src; ad[1] = msg->auth; ad[2] = &msg->subtype;
	al[0] = 6; al[1] = msg->auth_len; al[2] = 1;
	if (msg->encrypted_len < 16 || msg->encrypted_len - 16 > sizeof(plain->data)) return -1;
	plain->len = msg->encrypted_len - 16;
	if (!ks_aes_siv_decrypt(key, msg->encrypted, msg->encrypted_len,
				ad, al, 3, plain->data)) return 0;
	if (msg->encrypted_len >= 18 &&
	    !ks_aes_siv_decrypt(key, msg->encrypted, msg->encrypted_len - 2,
				ad, al, 3, plain->data)) {
		plain->len -= 2;
		return 0;
	}
	ks_secure_clear(plain, sizeof(*plain));
	return -1;
}

int ks_rrb_build(uint8_t subtype, const uint8_t src[6], const uint8_t dst[6],
		 const uint8_t key[32], const uint8_t *auth, size_t auth_len,
		 const uint8_t *plain, size_t plain_len, uint8_t *out,
		 size_t cap, size_t *out_len)
{
	uint8_t padded[KS_MAX_RRB_BODY], *pos; size_t palen = auth_len, body;
	const uint8_t *ad[3]; size_t al[3];
	if (!src || !dst || !key || (!auth && auth_len) || (!plain && plain_len) || !out || !out_len ||
	    auth_len > sizeof(padded) || plain_len > KS_MAX_RRB_BODY || subtype < 1 || subtype > 5) return -1;
	memcpy(padded, auth, auth_len); body = 2 + palen + 16 + plain_len;
	if (body < 64) {
		size_t pad = 64 - body; if (pad < 4) pad = 4;
		if (palen + pad > sizeof(padded)) return -1;
		ks_put_le16(padded + palen, 0); ks_put_le16(padded + palen + 2, (uint16_t) (pad - 4));
		memset(padded + palen + 4, 0, pad - 4); palen += pad;
	}
	if (20 + 2 + palen + 16 + plain_len > cap || palen > UINT16_MAX) return -1;
	memcpy(out, dst, 6); memcpy(out + 6, src, 6); out[12] = 0x88; out[13] = 0xb7;
	memcpy(out + 14, oui, sizeof(oui)); out[19] = subtype; ks_put_le16(out + 20, (uint16_t) palen);
	memcpy(out + 22, padded, palen); pos = out + 22 + palen;
	ad[0] = src; ad[1] = out + 22; ad[2] = out + 19; al[0] = 6; al[1] = palen; al[2] = 1;
	if (ks_aes_siv_encrypt(key, plain, plain_len, ad, al, 3, pos)) return -1;
	*out_len = 22 + palen + 16 + plain_len; return 0;
}

static int tlv_get(const uint8_t *p, size_t len, uint16_t wanted,
		   const uint8_t **value, size_t *value_len)
{
	int found = 0;
	while (len) {
		uint16_t t, n;
		if (len < 4) return -1;
		t = ks_get_le16(p); n = ks_get_le16(p + 2); p += 4; len -= 4;
		if (n > len) return -1;
		if (t == wanted) { if (found) return -1; found = 1; *value = p; *value_len = n; }
		p += n; len -= n;
	}
	return found;
}

static int need(const uint8_t *p, size_t len, uint16_t t, size_t exact, const uint8_t **v)
{
	size_t n = 0; int rc = tlv_get(p, len, t, v, &n);
	return rc == 1 && (!exact || n == exact) ? (int) n : -1;
}

static int exact(const uint8_t *p, size_t len, uint16_t t, size_t size,
		 const uint8_t **v)
{
	size_t n = 0;
	int rc = tlv_get(p, len, t, v, &n);
	if (rc <= 0) return rc;
	return n == size ? 1 : -1;
}

static int peer_by_message(const struct ks_state *s, const struct ks_rrb_message *m)
{
	const uint8_t *r0 = NULL;
	const uint8_t *r1 = NULL;
	int found = -1, r0n;
	size_t i;
	if ((r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 ||
	    r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0) return -1;
	for (i = 0; i < s->cfg.n_ft_peers; i++) {
		const struct ks_ft_peer *p = &s->cfg.ft_peers[i];
		if (!p->used || !ks_mac_equal(p->transport, m->src) ||
		    !((p->r0kh_id_len == (size_t) r0n &&
		       !CRYPTO_memcmp(p->r0kh_id, r0, (size_t) r0n)) ||
		      ks_mac_equal(p->r1kh_id, r1))) continue;
		if (found >= 0) return -1;
		found = (int) i;
	}
	return found;
}

static int local_bss_by_r0kh(const struct ks_state *s, const uint8_t *r0,
			      size_t r0n)
{
	int found = -1;
	size_t i;

	for (i = 0; i < s->cfg.n_bss; i++) {
		const struct ks_bss *b = &s->cfg.bss[i];
		if (!b->active || !b->mtk_kdp || b->r0kh_id_len != r0n ||
		    CRYPTO_memcmp(b->r0kh_id, r0, r0n)) continue;
		if (found >= 0) return -1;
		found = (int) i;
	}
	return found;
}

static int pull_message_ids(const struct ks_state *s, int pi,
			    const struct ks_rrb_message *m, int *bss)
{
	const struct ks_ft_peer *peer = &s->cfg.ft_peers[pi];
	const uint8_t *r0 = NULL, *r1 = NULL;
	int bi, r0n;

	if (!peer->used || !ks_mac_equal(peer->transport, m->src) ||
	    (r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 ||
	    r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0 ||
	    !ks_mac_equal(peer->r1kh_id, r1) ||
	    (bi = local_bss_by_r0kh(s, r0, (size_t) r0n)) < 0) return -1;
	if (bss) *bss = bi;
	return 0;
}

static int peer_by_pull(const struct ks_state *s, const struct ks_rrb_message *m)
{
	int found = -1;
	size_t i;

	for (i = 0; i < s->cfg.n_ft_peers; i++) {
		if (pull_message_ids(s, (int) i, m, NULL)) continue;
		if (found >= 0) return -1;
		found = (int) i;
	}
	return found;
}

static int next_seq(struct ks_ft_peer *p, uint8_t out[12])
{
	if (!p->tx_domain) {
		if (ks_random(&p->tx_domain, 4) || ks_random(&p->tx_seq, 4)) return -1;
		p->tx_domain |= 1;
	}
	ks_put_le32(out, p->tx_domain); ks_put_le32(out + 4, p->tx_seq++);
	ks_put_le32(out + 8, (uint32_t) (ks_now_ms() / 1000)); return 0;
}

static int seq_check(struct ks_ft_peer *p, const uint8_t seq[12])
{
	uint32_t dom = ks_get_le32(seq), n = ks_get_le32(seq + 4), ts = ks_get_le32(seq + 8);
	uint32_t off;
	int64_t remote_now, diff;
	unsigned int i;

	if (!p->rx_count || dom != p->rx_domain) return -2;
	remote_now = (int64_t) (ks_now_ms() / 1000) - p->rx_clock_offset;
	diff = (int64_t) (int32_t) (ts - (uint32_t) remote_now);
	if (diff < -10 || diff > 10) return -2;
	off = n - p->rx_last[p->rx_offset];
	if (off > 0xc0000000u) return -1;
	if (off > 0x40000000u) return -2;
	for (i = 0; i < p->rx_count; i++)
		if (p->rx_last[i] == n) return -1;
	return 0;
}

static void seq_accept(struct ks_ft_peer *p, const uint8_t seq[12])
{
	uint32_t n = ks_get_le32(seq + 4), base, off, min_off;
	unsigned int i, min = 0;

	if (p->rx_count < 16) {
		p->rx_last[p->rx_count++] = n;
		return;
	}
	base = p->rx_last[p->rx_offset];
	for (i = 0; i < p->rx_count; i++) {
		off = p->rx_last[i] - base;
		min_off = p->rx_last[min] - base;
		if (off < min_off && i != p->rx_offset) min = i;
	}
	p->rx_last[p->rx_offset] = n;
	p->rx_offset = min;
}

static void seq_reset(struct ks_ft_peer *p, const uint8_t seq[12], unsigned int queued)
{
	uint32_t n = ks_get_le32(seq + 4);
	p->rx_domain = ks_get_le32(seq); p->rx_count = 2; p->rx_offset = 0;
	p->rx_last[0] = n - 16 - queued; p->rx_last[1] = n;
	p->rx_clock_offset = (int64_t) (ks_now_ms() / 1000) -
		(int64_t) ks_get_le32(seq + 8);
}

static int message_ids(const struct ks_state *s, int pi,
		       const struct ks_rrb_message *m, bool local_target)
{
	const struct ks_ft_peer *peer = &s->cfg.ft_peers[pi];
	const uint8_t *r0 = NULL, *r1 = NULL;
	int r0n;

	if ((r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 ||
	    r0n > KS_MAX_R0KH_ID || need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0)
		return -1;
	if (!local_target && ks_mac_equal(r1, peer->r1kh_id)) return 0;
	if (ks_bss_by_r1kh(s, r1) < 0) return -1;
	if (peer->r0kh_id_len &&
	    (peer->r0kh_id_len != (size_t) r0n ||
	     CRYPTO_memcmp(peer->r0kh_id, r0, (size_t) r0n))) return -1;
	return 0;
}

static int send_seq_resp(struct ks_state *s, int pi, const struct ks_rrb_message *m)
{
	const uint8_t *nonce = NULL, *r0 = NULL, *r1 = NULL; int r0n; uint8_t seq[12], auth[256], frame[512];
	struct rb a = { auth, sizeof(auth), 0 }; size_t flen;
	if (message_ids(s, pi, m, false) ||
	    need(m->auth, m->auth_len, TLV_NONCE, 16, &nonce) < 0 ||
	    (r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 || r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0 || next_seq(&s->cfg.ft_peers[pi], seq)) return -1;
	if (tlv(&a, TLV_NONCE, nonce, 16) || tlv(&a, TLV_SEQ, seq, 12) || tlv(&a, TLV_R0KH_ID, r0, r0n) || tlv(&a, TLV_R1KH_ID, r1, 6) ||
	    ks_rrb_build(RRB_SEQ_RESP, s->transport_mac, m->src, s->rrb_key,
			 auth, a.len, NULL, 0, frame, sizeof(frame), &flen)) return -1;
	return ks_backend_send_rrb(s, m->src, frame, flen);
}

static int queue_and_sync(struct ks_state *s, int pi, const struct ks_rrb_message *m,
			  const uint8_t *frame0, size_t frame_len)
{
	const uint8_t *r0 = NULL, *r1 = NULL; int r0n; size_t i, flen; uint8_t nonce[16], auth[256], out[512];
	struct rb a = { auth, sizeof(auth), 0 }; struct ks_rrb_pending *q = NULL;
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s->rrb_pending[i].used && ks_mac_equal(s->rrb_pending[i].source, m->src))
			ks_secure_clear(&s->rrb_pending[i], sizeof(s->rrb_pending[i]));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (!s->rrb_pending[i].used) { q = &s->rrb_pending[i]; break; }
	if (!q || frame_len > sizeof(q->frame) || ks_random(nonce, sizeof(nonce)) ||
	    (r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 || r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0) return -1;
	memset(q, 0, sizeof(*q)); q->used = true; q->subtype = m->subtype;
	memcpy(q->source, m->src, 6); memcpy(q->nonce, nonce, 16);
	memcpy(q->frame, frame0, frame_len); q->frame_len = frame_len; q->deadline_ms = ks_now_ms() + 10000;
	if (tlv(&a, TLV_NONCE, nonce, 16) || tlv(&a, TLV_R0KH_ID, r0, r0n) || tlv(&a, TLV_R1KH_ID, r1, 6) ||
	    ks_rrb_build(RRB_SEQ_REQ, s->transport_mac, m->src, s->rrb_key,
			 auth, a.len, NULL, 0, out, sizeof(out), &flen) ||
	    ks_backend_send_rrb(s, m->src, out, flen)) { ks_secure_clear(q, sizeof(*q)); return -1; }
	(void) pi; return 0;
}

static int handle_key_record(struct ks_state *s, int pi, const struct ks_rrb_message *m,
			     const struct ks_rrb_plain *plain)
{
	const uint8_t *r0 = NULL, *r1 = NULL, *sta = NULL, *n0 = NULL;
	const uint8_t *n1 = NULL, *key = NULL, *pair = NULL, *exp = NULL;
	int r0n; uint32_t expires; int bss; struct ks_kdp_element e;
	if (message_ids(s, pi, m, true) ||
	    (r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 || r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0 ||
	    need(plain->data, plain->len, TLV_S1KH_ID, 6, &sta) < 0 ||
	    need(plain->data, plain->len, TLV_PMKR0_NAME, 16, &n0) < 0 ||
	    need(plain->data, plain->len, TLV_PMKR1_NAME, 16, &n1) < 0 ||
	    need(plain->data, plain->len, TLV_PMK_R1, 32, &key) < 0 ||
	    need(plain->data, plain->len, TLV_PAIRWISE, 2, &pair) < 0 ||
	    need(plain->data, plain->len, TLV_EXPIRES_IN, 2, &exp) < 0) return -1;
	if (s->cfg.ft_peers[pi].r0kh_id_len &&
	    (s->cfg.ft_peers[pi].r0kh_id_len != (size_t) r0n ||
	     CRYPTO_memcmp(s->cfg.ft_peers[pi].r0kh_id, r0, (size_t) r0n))) return -1;
	expires = ks_get_le16(exp); if (!expires || ks_get_le16(pair) != 0x10) return -1;
	bss = ks_bss_by_r1kh(s, r1); if (bss < 0 || !s->cfg.bss[bss].mtk_kdp) return -1;
	if (ks_kdp_from_rrb(&e, sta, r0, (size_t) r0n, n0, r1, n1, key,
			    s->cfg.ft_peers[pi].bssid, 0x10, expires)) return -1;
	if (ks_backend_ft_insert(s, bss, s->cfg.ft_peers[pi].peer_ip, &e)) {
		ks_secure_clear(&e, sizeof(e)); return -1;
	}
	ks_secure_clear(&e, sizeof(e)); return 0;
}

static int handle_pull(struct ks_state *s, int pi, int source_bss,
		       const struct ks_rrb_message *m,
		       const struct ks_rrb_plain *plain)
{
	const uint8_t *nonce = NULL, *sta = NULL, *n0 = NULL;
	uint8_t v = 0;
	size_t i;

	if (need(m->auth, m->auth_len, TLV_NONCE, 16, &nonce) < 0 ||
	    need(plain->data, plain->len, TLV_PMKR0_NAME, 16, &n0) < 0 ||
	    need(plain->data, plain->len, TLV_S1KH_ID, 6, &sta) < 0 ||
	    !ks_mac_unicast(sta)) return -1;
	for (i = 0; i < 16; i++) v |= n0[i];
	if (!v) return -1;
	return ks_kdp_pull_request(s, source_bss, pi, nonce, sta, n0);
}

static struct ks_pull_pending *pull_find(struct ks_state *s, int pi,
					 const uint8_t nonce[16])
{
	size_t i;
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s->pull_pending[i].used && s->pull_pending[i].peer_index == pi &&
		    !CRYPTO_memcmp(s->pull_pending[i].nonce, nonce, 16))
			return &s->pull_pending[i];
	return NULL;
}

static void pull_finish_group(struct ks_state *s,
			      const struct ks_pull_pending *pending)
{
	struct ks_pull_pending match;
	size_t i;

	memcpy(&match, pending, sizeof(match));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s->pull_pending[i].used &&
		    s->pull_pending[i].target_bss == match.target_bss &&
		    ks_mac_equal(s->pull_pending[i].sta, match.sta) &&
		    !CRYPTO_memcmp(s->pull_pending[i].pmkr0name, match.pmkr0name, 16))
			ks_secure_clear(&s->pull_pending[i], sizeof(s->pull_pending[i]));
	ks_secure_clear(&match, sizeof(match));
}

static int handle_pull_resp(struct ks_state *s, int pi,
                            const struct ks_rrb_message *m,
                            const struct ks_rrb_plain *plain)
{
	const uint8_t *nonce = NULL, *r0 = NULL, *r1 = NULL, *sta = NULL;
	const uint8_t *n1 = NULL, *key = NULL, *pair = NULL, *exp = NULL;
	struct ks_pull_pending *pending;
	struct ks_kdp_element e;
	uint32_t expires;
	int r0n, hn1, hkey, hpair, hexp, rc;

	if (message_ids(s, pi, m, true) ||
	    need(m->auth, m->auth_len, TLV_NONCE, 16, &nonce) < 0 ||
	    (r0n = need(m->auth, m->auth_len, TLV_R0KH_ID, 0, &r0)) < 1 ||
	    r0n > KS_MAX_R0KH_ID ||
	    need(m->auth, m->auth_len, TLV_R1KH_ID, 6, &r1) < 0) return -1;

	pending = pull_find(s, pi, nonce);
	if (!pending) return -1;

	if (pending->target_bss < 0 ||
	    (size_t) pending->target_bss >= s->cfg.n_bss ||
	    !ks_mac_equal(r1, s->cfg.bss[pending->target_bss].r1kh_id)) return -1;

	if (need(plain->data, plain->len, TLV_S1KH_ID, 6, &sta) < 0 ||
	    !ks_mac_equal(sta, pending->sta)) {
		ks_secure_clear(pending, sizeof(*pending));
		return -1;
	}

	hn1 = exact(plain->data, plain->len, TLV_PMKR1_NAME, 16, &n1);
	hkey = exact(plain->data, plain->len, TLV_PMK_R1, 32, &key);
	hpair = exact(plain->data, plain->len, TLV_PAIRWISE, 2, &pair);
	hexp = exact(plain->data, plain->len, TLV_EXPIRES_IN, 2, &exp);

	if (!hn1 && !hkey && !hpair && !hexp) {
		ks_secure_clear(pending, sizeof(*pending));
		return 0;
	}

	if (hn1 != 1 || hkey != 1 || hpair != 1 || hexp != 1) {
		ks_secure_clear(pending, sizeof(*pending));
		return -1;
	}

	expires = ks_get_le16(exp);
	if (ks_get_le16(pair) != 0x10 || !expires ||
	    ks_kdp_from_rrb(&e, sta, r0, (size_t) r0n,
	                    pending->pmkr0name, r1, n1, key,
	                    s->cfg.ft_peers[pi].bssid, 0x10, expires)) {
		ks_secure_clear(pending, sizeof(*pending));
		return -1;
	}

	rc = ks_backend_ft_insert(s, pending->target_bss,
	                          s->cfg.ft_peers[pi].peer_ip, &e);
	ks_secure_clear(&e, sizeof(e));

	if (!rc)
		pull_finish_group(s, pending);
	else
		ks_secure_clear(pending, sizeof(*pending));

	return rc;
}

static int handle_seq_resp(struct ks_state *s, int pi, const struct ks_rrb_message *m)
{
	const uint8_t *nonce = NULL, *seq = NULL; size_t i;
	if (need(m->auth, m->auth_len, TLV_NONCE, 16, &nonce) < 0 ||
	    need(m->auth, m->auth_len, TLV_SEQ, 12, &seq) < 0) return -1;
	for (i = 0; i < KS_MAX_RRB_PENDING; i++) {
		struct ks_rrb_pending q;
		if (!s->rrb_pending[i].used || !ks_mac_equal(s->rrb_pending[i].source, m->src) ||
		    CRYPTO_memcmp(s->rrb_pending[i].nonce, nonce, 16)) continue;
		if ((s->rrb_pending[i].subtype == RRB_PULL &&
		     pull_message_ids(s, pi, m, NULL)) ||
		    (s->rrb_pending[i].subtype != RRB_PULL &&
		     message_ids(s, pi, m, true))) return -1;
		memcpy(&q, &s->rrb_pending[i], sizeof(q)); ks_secure_clear(&s->rrb_pending[i], sizeof(s->rrb_pending[i]));
		seq_reset(&s->cfg.ft_peers[pi], seq, 1);
		ks_rrb_handle_frame(s, q.frame, q.frame_len);
		ks_secure_clear(&q, sizeof(q)); return 0;
	}
	return -1;
}

int ks_rrb_handle_frame(struct ks_state *s, const uint8_t *frame, size_t len)
{
	struct ks_rrb_message m;
	struct ks_rrb_plain p;
	int bss = -1, pi, rc = -1;
	const uint8_t *seq = NULL;

	if (!s->cfg.ft_enabled || !s->rrb_key_loaded ||
	    ks_rrb_parse_frame(frame, len, &m))
		return 0;

	if (!ks_mac_equal(m.dst, s->transport_mac) &&
	    ks_bss_by_bssid(s, m.dst) < 0) return 0;

	pi = m.subtype == RRB_PULL ? peer_by_pull(s, &m) : peer_by_message(s, &m);
	if (pi < 0) return 0;

	if (ks_rrb_decrypt(s->rrb_key, &m, &p)) return 0;

	switch (m.subtype) {
	case RRB_SEQ_REQ:
		rc = send_seq_resp(s, pi, &m);
		break;
	case RRB_SEQ_RESP:
		rc = handle_seq_resp(s, pi, &m);
		break;
	case RRB_PULL:
		if (pull_message_ids(s, pi, &m, &bss) ||
		    need(m.auth, m.auth_len, TLV_SEQ, 12, &seq) < 0) break;
		goto replay;
	case RRB_PUSH:
	case RRB_RESP:
		if (message_ids(s, pi, &m, true) ||
		    need(m.auth, m.auth_len, TLV_SEQ, 12, &seq) < 0) break;
	replay:
		rc = seq_check(&s->cfg.ft_peers[pi], seq);
		if (rc == -2) {
			rc = queue_and_sync(s, pi, &m, frame, len);
		} else if (rc == 0) {
			seq_accept(&s->cfg.ft_peers[pi], seq);
			if (m.subtype == RRB_PULL)
				rc = handle_pull(s, pi, bss, &m, &p);
			else if (m.subtype == RRB_PUSH)
				rc = handle_key_record(s, pi, &m, &p);
			else
				rc = handle_pull_resp(s, pi, &m, &p);
		}
		break;
	default:
		rc = 0;
		break;
	}

	ks_secure_clear(&p, sizeof(p));
	return rc;
}

static int send_pull_peer(struct ks_state *s, int target_bss,
                          const struct ks_kdp_element *e, size_t pi)
{
	struct ks_ft_peer *peer = &s->cfg.ft_peers[pi];
	struct ks_pull_pending *pending = NULL;
	uint8_t seq[12], auth[256], plain[128], frame[512], nonce[16];
	struct rb a = { auth, sizeof(auth), 0 }, p = { plain, sizeof(plain), 0 };
	uint64_t now;
	size_t flen;

	if (!peer->used || !peer->r0kh_id_len)
		return -1;

	now = ks_now_ms();

	for (size_t j = 0; j < KS_MAX_RRB_PENDING; j++) {
		struct ks_pull_pending *q = &s->pull_pending[j];

		if (!q->used ||
		    q->peer_index != (int) pi ||
		    !ks_mac_equal(q->sta, ks_kdp_sta(e)))
			continue;

		if (q->target_bss == target_bss &&
		    !CRYPTO_memcmp(q->pmkr0name, ks_kdp_pmkr0name(e), 16) &&
		    now < q->deadline_ms) return 0;

		ks_secure_clear(q, sizeof(*q));
	}

	if (ks_random(nonce, sizeof(nonce)) || next_seq(peer, seq))
		return -1;

	for (size_t j = 0; j < KS_MAX_RRB_PENDING; j++) {
		if (!s->pull_pending[j].used) {
			pending = &s->pull_pending[j];
			break;
		}
	}

	if (!pending)
		return -1;

	memset(pending, 0, sizeof(*pending));
	pending->used = true;
	memcpy(pending->nonce, nonce, 16);
	memcpy(pending->sta, ks_kdp_sta(e), 6);
	memcpy(pending->pmkr0name, ks_kdp_pmkr0name(e), 16);
	pending->peer_index = (int) pi;
	pending->target_bss = target_bss;
	pending->deadline_ms = now + 10000;

	if (tlv(&a, TLV_NONCE, nonce, 16) ||
	    tlv(&a, TLV_SEQ, seq, 12) ||
	    tlv(&a, TLV_R0KH_ID, peer->r0kh_id, peer->r0kh_id_len) ||
	    tlv(&a, TLV_R1KH_ID, s->cfg.bss[target_bss].r1kh_id, 6) ||
	    tlv(&p, TLV_PMKR0_NAME, ks_kdp_pmkr0name(e), 16) ||
	    tlv(&p, TLV_S1KH_ID, ks_kdp_sta(e), 6) ||
	    ks_rrb_build(RRB_PULL, s->transport_mac, peer->transport,
	                 s->rrb_key, auth, a.len, plain, p.len,
	                 frame, sizeof(frame), &flen) ||
	    ks_backend_send_rrb(s, peer->transport, frame, flen)) {
		ks_secure_clear(pending, sizeof(*pending));
		ks_secure_clear(plain, sizeof(plain));
		ks_secure_clear(frame, sizeof(frame));
		return -1;
	}

	ks_secure_clear(plain, sizeof(plain));
	ks_secure_clear(frame, sizeof(frame));
	return 0;
}

int ks_rrb_send_pull(struct ks_state *s, int target_bss,
		     const struct ks_kdp_element *e)
{
	const uint8_t *r0;
	size_t r0n, i, matches = 0;
	int sent = 0;

	if (!s || !e || target_bss < 0 || (size_t) target_bss >= s->cfg.n_bss ||
	    !s->cfg.bss[target_bss].active || !s->cfg.bss[target_bss].mtk_kdp ||
	    !ks_mac_equal(ks_kdp_r1kh(e), s->cfg.bss[target_bss].r1kh_id) ||
	    !memcmp(ks_kdp_pmkr0name(e), (uint8_t[16]) {0}, 16)) return -1;
	r0 = ks_kdp_r0kh_id(e, &r0n);
	if (r0n > KS_MAX_R0KH_ID) return -1;
	if (r0n) {
		for (i = 0; i < s->cfg.n_ft_peers; i++)
			if (s->cfg.ft_peers[i].used && s->cfg.ft_peers[i].r0kh_id_len == r0n &&
			    !CRYPTO_memcmp(s->cfg.ft_peers[i].r0kh_id, r0, r0n)) matches++;
		if (matches != 1) return -1;
	}
	for (i = 0; i < s->cfg.n_ft_peers; i++) {
		struct ks_ft_peer *peer = &s->cfg.ft_peers[i];
		if (!peer->used || !peer->r0kh_id_len ||
		    (r0n && (peer->r0kh_id_len != r0n ||
		     CRYPTO_memcmp(peer->r0kh_id, r0, r0n))) ||
		    (!r0n && peer->learned && peer->ssid[0] &&
		     strcmp(peer->ssid, s->cfg.bss[target_bss].ssid))) continue;
		if (!send_pull_peer(s, target_bss, e, i)) sent++;
	}
	return sent ? 0 : -1;
}

int ks_rrb_send_push(struct ks_state *s, int peer_index, const struct ks_kdp_element *e)
{
	struct ks_ft_peer *peer; uint8_t seq[12], auth[256], plain[256], frame[768];
	struct rb a = { auth, sizeof(auth), 0 }, p = { plain, sizeof(plain), 0 };
	const uint8_t *r0; size_t r0n, flen; uint8_t pair[2], expires[2]; uint32_t life;
	if (peer_index < 0 || (size_t) peer_index >= s->cfg.n_ft_peers || !e) return -1;
	peer = &s->cfg.ft_peers[peer_index]; r0 = ks_kdp_r0kh_id(e, &r0n);
	if (!r0n || r0n > KS_MAX_R0KH_ID || !ks_mac_equal(peer->r1kh_id, ks_kdp_r1kh(e)) || next_seq(peer, seq)) return -1;
	life = ks_kdp_lifetime(e); if (!life) life = 1; if (life > 3600) life = 3600;
	ks_put_le16(pair, 0x10); ks_put_le16(expires, (uint16_t) life);
	if (tlv(&a, TLV_SEQ, seq, 12) || tlv(&a, TLV_R0KH_ID, r0, r0n) || tlv(&a, TLV_R1KH_ID, peer->r1kh_id, 6) ||
	    tlv(&p, TLV_S1KH_ID, ks_kdp_sta(e), 6) || tlv(&p, TLV_PMKR0_NAME, ks_kdp_pmkr0name(e), 16) ||
	    tlv(&p, TLV_PMK_R1, ks_kdp_pmkr1(e), 32) || tlv(&p, TLV_PMKR1_NAME, ks_kdp_pmkr1name(e), 16) ||
	    tlv(&p, TLV_PAIRWISE, pair, 2) || tlv(&p, TLV_EXPIRES_IN, expires, 2) ||
	    ks_rrb_build(RRB_PUSH, s->transport_mac, peer->transport, s->rrb_key,
			 auth, a.len, plain, p.len, frame, sizeof(frame), &flen)) goto bad;
	if (ks_backend_send_rrb(s, peer->transport, frame, flen)) goto bad;
	ks_secure_clear(plain, sizeof(plain)); ks_secure_clear(frame, sizeof(frame)); return 0;
bad:
	ks_secure_clear(plain, sizeof(plain)); ks_secure_clear(frame, sizeof(frame)); return -1;
}

int ks_rrb_send_resp(struct ks_state *s, int peer_index, int source_bss,
		     const uint8_t nonce[16], const uint8_t sta[6],
		     const struct ks_kdp_element *e)
{
	struct ks_ft_peer *peer;
	struct ks_bss *bss;
	uint8_t seq[12], auth[256], plain[256], frame[768], pair[2], expires[2];
	struct rb a = { auth, sizeof(auth), 0 }, p = { plain, sizeof(plain), 0 };
	uint32_t life;
	size_t flen;

	if (!s || !nonce || !sta || peer_index < 0 ||
	    (size_t) peer_index >= s->cfg.n_ft_peers || source_bss < 0 ||
	    (size_t) source_bss >= s->cfg.n_bss || !ks_mac_unicast(sta)) return -1;
	peer = &s->cfg.ft_peers[peer_index]; bss = &s->cfg.bss[source_bss];
	if (!peer->used || !bss->active || !bss->mtk_kdp || !bss->r0kh_id_len ||
	    next_seq(peer, seq)) return -1;
	if (tlv(&a, TLV_NONCE, nonce, 16) || tlv(&a, TLV_SEQ, seq, 12) ||
	    tlv(&a, TLV_R0KH_ID, bss->r0kh_id, bss->r0kh_id_len) ||
	    tlv(&a, TLV_R1KH_ID, peer->r1kh_id, 6) ||
	    tlv(&p, TLV_S1KH_ID, sta, 6)) goto bad_resp;
	if (e) {
		if (!ks_mac_equal(ks_kdp_sta(e), sta) ||
		    !ks_mac_equal(ks_kdp_r1kh(e), peer->r1kh_id)) goto bad_resp;
		life = ks_kdp_lifetime(e); if (!life) life = 1; if (life > 3600) life = 3600;
		ks_put_le16(pair, 0x10); ks_put_le16(expires, (uint16_t) life);
		if (tlv(&p, TLV_PMK_R1, ks_kdp_pmkr1(e), 32) ||
		    tlv(&p, TLV_PMKR1_NAME, ks_kdp_pmkr1name(e), 16) ||
		    tlv(&p, TLV_PAIRWISE, pair, 2) ||
		    tlv(&p, TLV_EXPIRES_IN, expires, 2)) goto bad_resp;
	}
	if (ks_rrb_build(RRB_RESP, s->transport_mac, peer->transport, s->rrb_key,
			 auth, a.len, plain, p.len, frame, sizeof(frame), &flen) ||
	    ks_backend_send_rrb(s, peer->transport, frame, flen)) goto bad_resp;
	ks_secure_clear(plain, sizeof(plain)); ks_secure_clear(frame, sizeof(frame)); return 0;
bad_resp:
	ks_secure_clear(plain, sizeof(plain)); ks_secure_clear(frame, sizeof(frame)); return -1;
}

void ks_rrb_expire(struct ks_state *s, uint64_t now)
{
	size_t i; for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s->rrb_pending[i].used && now >= s->rrb_pending[i].deadline_ms)
			ks_secure_clear(&s->rrb_pending[i], sizeof(s->rrb_pending[i]));
	for (i = 0; i < KS_MAX_RRB_PENDING; i++)
		if (s->pull_pending[i].used && now >= s->pull_pending[i].deadline_ms)
			ks_secure_clear(&s->pull_pending[i], sizeof(s->pull_pending[i]));
}
