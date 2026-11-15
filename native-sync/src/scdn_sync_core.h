#ifndef SCDN_SYNC_CORE_H
#define SCDN_SYNC_CORE_H

#include <stddef.h>

#define SCDN_SYNC_NATIVE_VERSION "0.2.0"
#define SCDN_SYNC_PROTOCOL "scdn.sync.v1"
#define SCDN_SYNC_MAX_ID 96
#define SCDN_SYNC_MAX_PEERS 1024
#define SCDN_SYNC_TOKEN_MIN 43
#define SCDN_SYNC_TOKEN_MAX 128

typedef enum {
    SCDN_SYNC_OFF = 0,
    SCDN_SYNC_MASTER,
    SCDN_SYNC_NODE,
    SCDN_SYNC_INVALID
} scdn_sync_role_t;

scdn_sync_role_t scdn_sync_parse_role(const unsigned char *value, size_t length);
const char *scdn_sync_role_name(scdn_sync_role_t role);
int scdn_sync_valid_id(const unsigned char *value, size_t length);
int scdn_sync_valid_token(const unsigned char *value, size_t length);
int scdn_sync_decode_fingerprint(const unsigned char *value, size_t length,
    unsigned char output[32]);
int scdn_sync_secure_equal(const unsigned char *a, size_t a_length,
    const unsigned char *b, size_t b_length);
void scdn_sync_clear(void *value, size_t length);

#endif
