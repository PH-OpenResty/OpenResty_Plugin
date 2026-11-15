#ifndef SCDN_SYNC_BUNDLE_H
#define SCDN_SYNC_BUNDLE_H
#include "scdn_sync_snapshot.h"
#include <openssl/evp.h>
#define SYNC_BUNDLE_MAX (16 * 1024 * 1024)
#define SYNC_BUNDLE_HEADER 320

EVP_PKEY *scdn_sync_key_load(const char *path, int private_key, int type);
u_char *scdn_sync_seal(const u_char *plain, size_t length, uint64_t sequence,
    const ngx_str_t *node, const ngx_str_t *scope, EVP_PKEY *sign, EVP_PKEY *encrypt,
    size_t *size);
u_char *scdn_sync_unseal(const u_char *envelope, size_t length,
    const ngx_str_t *node, const ngx_str_t *scope, EVP_PKEY *verify, EVP_PKEY *decrypt,
    uint64_t *sequence, size_t *size);
uint64_t scdn_sync_u64(const u_char *p);
void scdn_sync_put64(u_char *p, uint64_t value);
int scdn_sync_signature_valid(const u_char *bytes, size_t size, EVP_PKEY *key);
#endif
