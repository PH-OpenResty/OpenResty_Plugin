#include "scdn_sync_bundle.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

uint64_t scdn_sync_u64(const u_char *p)
{
    unsigned i; uint64_t n = 0;
    for (i = 0; i < 8; i++) n = (n << 8) | p[i];
    return n;
}
void scdn_sync_put64(u_char *p, uint64_t n)
{
    unsigned i;
    for (i = 0; i < 8; i++) { p[7 - i] = (u_char) n; n >>= 8; }
}
EVP_PKEY *scdn_sync_key_load(const char *path, int private_key, int type)
{
    u_char *bytes;
    size_t length;
    BIO *bio;
    EVP_PKEY *key = NULL;
    bytes = scdn_sync_read_file(path, 65536, &length, private_key);
    if (!bytes) return NULL;
    bio = BIO_new_mem_buf(bytes, (int) length);
    if (bio) {
        key = private_key ? PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *) "")
                          : PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    OPENSSL_cleanse(bytes, length); free(bytes);
    if (key && (EVP_PKEY_base_id(key) != type
        || (type == EVP_PKEY_RSA && (EVP_PKEY_bits(key) < 2048 || EVP_PKEY_bits(key) > 8192))))
    { EVP_PKEY_free(key); key = NULL; }
    return key;
}
static int rsa_key(EVP_PKEY *key, const u_char *input, size_t n, u_char *output, size_t *size, int decrypt)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    int ok = 0;
    if (!ctx) return 0;
    if ((decrypt ? EVP_PKEY_decrypt_init(ctx) : EVP_PKEY_encrypt_init(ctx)) <= 0
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
        || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0
        || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto finish;
    ok = (decrypt ? EVP_PKEY_decrypt(ctx, output, size, input, n)
                  : EVP_PKEY_encrypt(ctx, output, size, input, n)) > 0;
finish:
    EVP_PKEY_CTX_free(ctx); return ok;
}
static int signature(EVP_PKEY *key, const u_char *bytes, size_t n, u_char sig[64], int verify)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t length = 64;
    int ok = 0;
    if (!ctx) return 0;
    if (verify) {
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1)
            ok = EVP_DigestVerify(ctx, sig, 64, bytes, n) == 1;
    } else if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1)
        ok = EVP_DigestSign(ctx, sig, &length, bytes, n) == 1 && length == 64;
    EVP_MD_CTX_free(ctx); return ok;
}
int scdn_sync_signature_valid(const u_char *bytes, size_t size, EVP_PKEY *key)
{
    return size >= SYNC_BUNDLE_HEADER + 64 && !memcmp(bytes, "SCNBND02", 8)
        && signature(key, bytes, size - 64, (u_char *) bytes + size - 64, 1);
}
u_char *scdn_sync_seal(const u_char *plain, size_t length, uint64_t sequence,
    const ngx_str_t *node, const ngx_str_t *scope, EVP_PKEY *sign, EVP_PKEY *encrypt, size_t *size)
{
    u_char *out = NULL, cek[32], wrapped[1024];
    size_t wrapped_size = sizeof(wrapped), total;
    int n, final, ok = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    if (!length || length > SYNC_BUNDLE_MAX || !sequence || node->len > 96 || scope->len > 96
        || RAND_bytes(cek, 32) != 1 || !rsa_key(encrypt, cek, 32, wrapped, &wrapped_size, 0)) goto finish;
    total = SYNC_BUNDLE_HEADER + wrapped_size + length + 64;
    out = calloc(1, total); if (!out) goto finish;
    memcpy(out, "SCNBND02", 8); scdn_sync_put64(out + 8, sequence);
    scdn_sync_put64(out + 16, (uint64_t) time(NULL));
    scdn_sync_put64(out + 24, (uint64_t) time(NULL) + 86400);
    scdn_sync_put64(out + 32, length); scdn_sync_put64(out + 40, wrapped_size);
    out[48] = (u_char) node->len; out[49] = (u_char) scope->len;
    memcpy(out + 56, node->data, node->len); memcpy(out + 152, scope->data, scope->len);
    scdn_sync_digest(plain, length, out + 248);
    if (RAND_bytes(out + 280, 12) != 1) goto finish;
    memcpy(out + SYNC_BUNDLE_HEADER, wrapped, wrapped_size);
    ctx = EVP_CIPHER_CTX_new(); if (!ctx) goto finish;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cek, out + 280) != 1
        || EVP_EncryptUpdate(ctx, NULL, &n, out, 292) != 1
        || EVP_EncryptUpdate(ctx, out + SYNC_BUNDLE_HEADER + wrapped_size, &n, plain, (int) length) != 1
        || (size_t) n != length
        || EVP_EncryptFinal_ex(ctx, out + SYNC_BUNDLE_HEADER + wrapped_size + n, &final) != 1
        || final != 0 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + 292) != 1
        || !signature(sign, out, total - 64, out + total - 64, 0)) goto finish;
    *size = total; ok = 1;
finish:
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(cek, sizeof(cek));
    if (!ok) { free(out); out = NULL; }
    return out;
}
u_char *scdn_sync_unseal(const u_char *in, size_t length,
    const ngx_str_t *node, const ngx_str_t *scope, EVP_PKEY *verify, EVP_PKEY *decrypt,
    uint64_t *sequence, size_t *size)
{
    size_t plain_size, wrapped_size, cek_size = 1024, i;
    u_char cek[1024], digest[32], *plain = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int n, final, ok = 0;
    uint64_t now = (uint64_t) time(NULL);
    if (length < SYNC_BUNDLE_HEADER + 64 || memcmp(in, "SCNBND02", 8)
        || scdn_sync_u64(in + 32) > SYNC_BUNDLE_MAX || scdn_sync_u64(in + 40) > 1024) return NULL;
    plain_size = (size_t) scdn_sync_u64(in + 32); wrapped_size = (size_t) scdn_sync_u64(in + 40);
    if (!plain_size || wrapped_size < 256 || length != SYNC_BUNDLE_HEADER + 64 + wrapped_size + plain_size
        || !scdn_sync_u64(in + 8) || in[48] != node->len || in[49] != scope->len
        || memcmp(in + 56, node->data, node->len) || memcmp(in + 152, scope->data, scope->len)
        || scdn_sync_u64(in + 16) > now + 30 || scdn_sync_u64(in + 24) <= now
        || scdn_sync_u64(in + 24) < scdn_sync_u64(in + 16)
        || scdn_sync_u64(in + 24) - scdn_sync_u64(in + 16) > 86400
        || !signature(verify, in, length - 64, (u_char *) in + length - 64, 1)) return NULL;
    for (i = 50; i < 56; i++) if (in[i]) return NULL;
    for (i = 56 + node->len; i < 152; i++) if (in[i]) return NULL;
    for (i = 152 + scope->len; i < 248; i++) if (in[i]) return NULL;
    for (i = 308; i < SYNC_BUNDLE_HEADER; i++) if (in[i]) return NULL;
    if (!rsa_key(decrypt, in + SYNC_BUNDLE_HEADER, wrapped_size, cek, &cek_size, 1) || cek_size != 32) goto finish;
    plain = malloc(plain_size + 1); ctx = EVP_CIPHER_CTX_new();
    if (!plain || !ctx) goto finish;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cek, in + 280) != 1
        || EVP_DecryptUpdate(ctx, NULL, &n, in, 292) != 1
        || EVP_DecryptUpdate(ctx, plain, &n, in + SYNC_BUNDLE_HEADER + wrapped_size, (int) plain_size) != 1
        || (size_t) n != plain_size
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *) (in + 292)) != 1
        || EVP_DecryptFinal_ex(ctx, plain + n, &final) != 1 || final != 0) goto finish;
    scdn_sync_digest(plain, plain_size, digest);
    if (memcmp(digest, in + 248, 32)) goto finish;
    plain[plain_size] = 0; *size = plain_size; *sequence = scdn_sync_u64(in + 8); ok = 1;
finish:
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(cek, sizeof(cek));
    if (!ok) { if (plain) OPENSSL_cleanse(plain, plain_size); free(plain); plain = NULL; }
    return plain;
}
