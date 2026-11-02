/*
 * GmSSL 交叉验证 oracle（C，链接 libgmssl.a）
 *
 * 目的：用 GmSSL 的实现重算雁书测试向量里的每一个字节，供
 * `scripts/crosscheck/crosscheck.py` 与 Rust 侧逐字节比对。
 *
 * 关键点：`rand_bytes` 由本文件提供（链接时优先于 libgmssl.a 里的 rand.o），
 * 传入固定 k 时 GmSSL 的 SM2 加解密/签名就是确定性的，因此可以做到**逐字节**比对，
 * 而不是"只验签通过"。
 *
 * 构建见 scripts/crosscheck/run.sh（不手写 gcc 命令）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>

static uint8_t g_fixed_k[32];
static int g_fixed_k_set = 0;

/* 覆盖 GmSSL 的 rand_bytes：设了固定 k 就返回 k（32 字节请求），否则读 /dev/urandom */
int rand_bytes(uint8_t *buf, size_t len)
{
	if (g_fixed_k_set && len == 32) {
		memcpy(buf, g_fixed_k, 32);
		return 1;
	}
	FILE *fp = fopen("/dev/urandom", "rb");
	if (!fp) {
		return -1;
	}
	size_t n = fread(buf, 1, len, fp);
	fclose(fp);
	return n == len ? 1 : -1;
}

static void die(const char *msg)
{
	fprintf(stderr, "oracle: %s\n", msg);
	exit(2);
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t max)
{
	size_t n = strlen(hex);
	if (n % 2 != 0) {
		die("odd hex length");
	}
	if (n / 2 > max) {
		die("hex too long");
	}
	for (size_t i = 0; i < n / 2; i++) {
		unsigned v;
		if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
			die("bad hex");
		}
		out[i] = (uint8_t)v;
	}
	return n / 2;
}

static void print_hex(const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		printf("%02x", b[i]);
	}
}

static uint8_t *alloc_hex(const char *hex, size_t *len)
{
	size_t n = strlen(hex) / 2;
	uint8_t *buf = malloc(n ? n : 1);
	if (!buf) {
		die("oom");
	}
	*len = hex2bin(hex, buf, n ? n : 1);
	return buf;
}

static void set_fixed_k(const char *hex)
{
	size_t len = 0;
	uint8_t *buf = alloc_hex(hex, &len);
	if (len != 32) {
		die("k must be 32 bytes");
	}
	memcpy(g_fixed_k, buf, 32);
	g_fixed_k_set = 1;
	free(buf);
}

static void key_from_priv(SM2_KEY *key, const uint8_t priv[32])
{
	memcpy(key->private_key, priv, 32);
	if (sm2_point_mul_generator(&key->public_key, priv) != 1) {
		die("sm2_point_mul_generator failed");
	}
}

static void key_from_pub(SM2_KEY *key, const uint8_t pub[64])
{
	memset(key, 0, sizeof(*key));
	memcpy(key->public_key.x, pub, 32);
	memcpy(key->public_key.y, pub + 32, 32);
}

static void hmac_sm3(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen,
		     uint8_t out[32])
{
	sm3_hmac(key, keylen, data, datalen, out);
}

/* HKDF-SM3（RFC 5869 结构，PRF = HMAC-SM3） */
static void hkdf_sm3(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
		     const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen)
{
	uint8_t prk[32];
	uint8_t zero[32] = {0};
	if (saltlen == 0) {
		hmac_sm3(zero, 32, ikm, ikmlen, prk);
	} else {
		hmac_sm3(salt, saltlen, ikm, ikmlen, prk);
	}

	uint8_t t[32];
	size_t tlen = 0;
	size_t produced = 0;
	uint8_t counter = 1;
	while (produced < outlen) {
		uint8_t buf[32 + 4096 + 1];
		size_t n = 0;
		if (infolen > 4096) {
			die("info too long");
		}
		memcpy(buf, t, tlen);
		n += tlen;
		memcpy(buf + n, info, infolen);
		n += infolen;
		buf[n++] = counter;
		hmac_sm3(prk, 32, buf, n, t);
		tlen = 32;
		size_t take = (outlen - produced) < 32 ? (outlen - produced) : 32;
		memcpy(out + produced, t, take);
		produced += take;
		counter++;
	}
}

static int cmd_sm3(int argc, char **argv)
{
	if (argc < 3) die("usage: sm3 <hex>");
	size_t len = 0;
	uint8_t *in = alloc_hex(argv[2], &len);
	uint8_t dgst[32];
	sm3_digest(in, len, dgst);
	print_hex(dgst, 32);
	printf("\n");
	free(in);
	return 0;
}

static int cmd_hmac(int argc, char **argv)
{
	if (argc < 4) die("usage: hmac-sm3 <key> <msg>");
	size_t kl = 0, ml = 0;
	uint8_t *k = alloc_hex(argv[2], &kl);
	uint8_t *m = alloc_hex(argv[3], &ml);
	uint8_t tag[32];
	hmac_sm3(k, kl, m, ml, tag);
	print_hex(tag, 32);
	printf("\n");
	free(k);
	free(m);
	return 0;
}

static int cmd_hkdf(int argc, char **argv)
{
	if (argc < 6) die("usage: hkdf <salt> <ikm> <info> <len>");
	size_t sl = 0, il = 0, nl = 0;
	uint8_t *salt = alloc_hex(argv[2], &sl);
	uint8_t *ikm = alloc_hex(argv[3], &il);
	uint8_t *info = alloc_hex(argv[4], &nl);
	size_t outlen = (size_t)strtoul(argv[5], NULL, 10);
	uint8_t *out = malloc(outlen ? outlen : 1);
	if (!out) die("oom");
	hkdf_sm3(salt, sl, ikm, il, info, nl, out, outlen);
	print_hex(out, outlen);
	printf("\n");
	free(salt);
	free(ikm);
	free(info);
	free(out);
	return 0;
}

static int cmd_gcm_enc(int argc, char **argv)
{
	if (argc < 6) die("usage: gcm-enc <key> <nonce> <aad> <pt>");
	size_t kl = 0, nl = 0, al = 0, pl = 0;
	uint8_t *key = alloc_hex(argv[2], &kl);
	uint8_t *nonce = alloc_hex(argv[3], &nl);
	uint8_t *aad = alloc_hex(argv[4], &al);
	uint8_t *pt = alloc_hex(argv[5], &pl);
	if (kl != 16) die("key must be 16 bytes");

	SM4_KEY sm4key;
	sm4_set_encrypt_key(&sm4key, key);
	uint8_t *ct = malloc(pl ? pl : 1);
	uint8_t tag[16];
	if (!ct) die("oom");
	if (sm4_gcm_encrypt(&sm4key, nonce, nl, aad, al, pt, pl, ct, 16, tag) != 1) {
		die("sm4_gcm_encrypt failed");
	}
	/* 输出 ct||tag 连写（tag 固定 16 字节 → 末尾 32 个 hex 字符） */
	print_hex(ct, pl);
	print_hex(tag, 16);
	printf("\n");
	free(key);
	free(nonce);
	free(aad);
	free(pt);
	free(ct);
	return 0;
}

static int cmd_gcm_dec(int argc, char **argv)
{
	if (argc < 7) die("usage: gcm-dec <key> <nonce> <aad> <ct> <tag>");
	size_t kl = 0, nl = 0, al = 0, cl = 0, tl = 0;
	uint8_t *key = alloc_hex(argv[2], &kl);
	uint8_t *nonce = alloc_hex(argv[3], &nl);
	uint8_t *aad = alloc_hex(argv[4], &al);
	uint8_t *ct = alloc_hex(argv[5], &cl);
	uint8_t *tag = alloc_hex(argv[6], &tl);
	if (kl != 16 || tl != 16) die("key/tag must be 16 bytes");

	SM4_KEY sm4key;
	sm4_set_encrypt_key(&sm4key, key);
	uint8_t *pt = malloc(cl ? cl : 1);
	if (!pt) die("oom");
	if (sm4_gcm_decrypt(&sm4key, nonce, nl, aad, al, ct, cl, tag, 16, pt) != 1) {
		free(pt);
		free(key);
		free(nonce);
		free(aad);
		free(ct);
		free(tag);
		printf("FAIL\n");
		return 1;
	}
	print_hex(pt, cl);
	printf("\n");
	free(key);
	free(nonce);
	free(aad);
	free(ct);
	free(tag);
	free(pt);
	return 0;
}

static int cmd_sm2_pub(int argc, char **argv)
{
	if (argc < 3) die("usage: sm2-pub <priv>");
	size_t kl = 0;
	uint8_t *priv = alloc_hex(argv[2], &kl);
	if (kl != 32) die("priv must be 32 bytes");
	SM2_KEY key;
	key_from_priv(&key, priv);
	print_hex(key.public_key.x, 32);
	print_hex(key.public_key.y, 32);
	printf("\n");
	free(priv);
	return 0;
}

static int cmd_sm2_za(int argc, char **argv)
{
	if (argc < 3) die("usage: sm2-za <pub>");
	size_t pl = 0;
	uint8_t *pub = alloc_hex(argv[2], &pl);
	if (pl != 64) die("pub must be 64 bytes");
	SM2_KEY key;
	key_from_pub(&key, pub);
	uint8_t z[32];
	if (sm2_compute_z(z, &key.public_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		die("sm2_compute_z failed");
	}
	print_hex(z, 32);
	printf("\n");
	free(pub);
	return 0;
}

static int cmd_sm2_enc(int argc, char **argv, int fixed)
{
	if (fixed) {
		if (argc < 5) die("usage: sm2-enc <pub> <k> <msg>");
		set_fixed_k(argv[3]);
	} else {
		if (argc < 4) die("usage: sm2-enc-rand <pub> <msg>");
	}
	int off = fixed ? 2 : 2;
	size_t pl = 0, ml = 0;
	uint8_t *pub = alloc_hex(argv[off], &pl);
	uint8_t *msg = alloc_hex(argv[off + (fixed ? 2 : 1)], &ml);
	if (pl != 64) die("pub must be 64 bytes");
	if (ml == 0 || ml > SM2_MAX_PLAINTEXT_SIZE) die("msg length out of range");

	SM2_KEY key;
	key_from_pub(&key, pub);
	SM2_CIPHERTEXT ct;
	memset(&ct, 0, sizeof(ct));
	if (sm2_do_encrypt(&key, msg, ml, &ct) != 1) die("sm2_do_encrypt failed");
	print_hex(ct.point.x, 32);
	print_hex(ct.point.y, 32);
	print_hex(ct.hash, 32);
	print_hex(ct.ciphertext, ct.ciphertext_size);
	printf("\n");
	free(pub);
	free(msg);
	return 0;
}

static int cmd_sm2_dec(int argc, char **argv)
{
	if (argc < 4) die("usage: sm2-dec <priv> <ciphertext>");
	size_t kl = 0, cl = 0;
	uint8_t *priv = alloc_hex(argv[2], &kl);
	uint8_t *raw = alloc_hex(argv[3], &cl);
	if (kl != 32) die("priv must be 32 bytes");
	if (cl < 96 || cl > 96 + SM2_MAX_PLAINTEXT_SIZE) die("ciphertext length");

	SM2_KEY key;
	key_from_priv(&key, priv);
	SM2_CIPHERTEXT ct;
	memset(&ct, 0, sizeof(ct));
	memcpy(ct.point.x, raw, 32);
	memcpy(ct.point.y, raw + 32, 32);
	memcpy(ct.hash, raw + 64, 32);
	ct.ciphertext_size = (uint8_t)(cl - 96);
	memcpy(ct.ciphertext, raw + 96, cl - 96);

	uint8_t out[SM2_MAX_PLAINTEXT_SIZE];
	size_t outlen = 0;
	if (sm2_do_decrypt(&key, &ct, out, &outlen) != 1) {
		printf("FAIL\n");
		return 1;
	}
	print_hex(out, outlen);
	printf("\n");
	free(priv);
	free(raw);
	return 0;
}

static int cmd_sm2_sign(int argc, char **argv, int fixed)
{
	if (fixed) {
		if (argc < 5) die("usage: sm2-sign <priv> <k> <msg>");
		set_fixed_k(argv[3]);
	} else {
		if (argc < 4) die("usage: sm2-sign-rand <priv> <msg>");
	}
	size_t kl = 0, ml = 0;
	uint8_t *priv = alloc_hex(argv[2], &kl);
	uint8_t *msg = alloc_hex(argv[fixed ? 4 : 3], &ml);
	if (kl != 32) die("priv must be 32 bytes");

	SM2_KEY key;
	key_from_priv(&key, priv);
	SM2_SIGN_CTX ctx;
	if (sm2_sign_init(&ctx, &key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		die("sm2_sign_init failed");
	}
	if (sm2_sign_update(&ctx, msg, ml) != 1) die("sm2_sign_update failed");
	uint8_t der[80];
	size_t derlen = sizeof(der);
	if (sm2_sign_finish(&ctx, der, &derlen) != 1) die("sm2_sign_finish failed");

	SM2_SIGNATURE sig;
	const uint8_t *p = der;
	size_t plen = derlen;
	if (sm2_signature_from_der(&sig, &p, &plen) != 1) die("sm2_signature_from_der failed");
	print_hex(sig.r, 32);
	print_hex(sig.s, 32);
	printf("\n");
	free(priv);
	free(msg);
	return 0;
}

static int cmd_sm2_verify(int argc, char **argv)
{
	if (argc < 5) die("usage: sm2-verify <pub> <msg> <sig>");
	size_t pl = 0, ml = 0, sl = 0;
	uint8_t *pub = alloc_hex(argv[2], &pl);
	uint8_t *msg = alloc_hex(argv[3], &ml);
	uint8_t *raw = alloc_hex(argv[4], &sl);
	if (pl != 64) die("pub must be 64 bytes");
	if (sl != 64) die("sig must be 64 bytes");

	SM2_KEY key;
	key_from_pub(&key, pub);

	uint8_t z[32];
	if (sm2_compute_z(z, &key.public_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		die("sm2_compute_z failed");
	}
	SM3_CTX sctx;
	uint8_t dgst[32];
	sm3_init(&sctx);
	sm3_update(&sctx, z, 32);
	sm3_update(&sctx, msg, ml);
	sm3_finish(&sctx, dgst);

	SM2_SIGNATURE sig;
	memcpy(sig.r, raw, 32);
	memcpy(sig.s, raw + 32, 32);
	int ok = sm2_do_verify(&key, dgst, &sig);
	printf("%s\n", ok == 1 ? "OK" : "FAIL");
	free(pub);
	free(msg);
	free(raw);
	return ok == 1 ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc < 2) die("subcommand required");
	const char *cmd = argv[1];
	if (!strcmp(cmd, "sm3")) return cmd_sm3(argc, argv);
	if (!strcmp(cmd, "hmac-sm3")) return cmd_hmac(argc, argv);
	if (!strcmp(cmd, "hkdf")) return cmd_hkdf(argc, argv);
	if (!strcmp(cmd, "gcm-enc")) return cmd_gcm_enc(argc, argv);
	if (!strcmp(cmd, "gcm-dec")) return cmd_gcm_dec(argc, argv);
	if (!strcmp(cmd, "sm2-pub")) return cmd_sm2_pub(argc, argv);
	if (!strcmp(cmd, "sm2-za")) return cmd_sm2_za(argc, argv);
	if (!strcmp(cmd, "sm2-enc")) return cmd_sm2_enc(argc, argv, 1);
	if (!strcmp(cmd, "sm2-enc-rand")) return cmd_sm2_enc(argc, argv, 0);
	if (!strcmp(cmd, "sm2-dec")) return cmd_sm2_dec(argc, argv);
	if (!strcmp(cmd, "sm2-sign")) return cmd_sm2_sign(argc, argv, 1);
	if (!strcmp(cmd, "sm2-sign-rand")) return cmd_sm2_sign(argc, argv, 0);
	if (!strcmp(cmd, "sm2-verify")) return cmd_sm2_verify(argc, argv);
	die("unknown subcommand");
	return 2;
}
