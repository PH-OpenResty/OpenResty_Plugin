#include "scdn_sync_core.h"

#include <string.h>

static int
scdn_sync_alphanumeric(unsigned char value)
{
    return (value >= 'A' && value <= 'Z')
           || (value >= 'a' && value <= 'z')
           || (value >= '0' && value <= '9');
}

scdn_sync_role_t
scdn_sync_parse_role(const unsigned char *value, size_t length)
{
    if (value == NULL) {
        return SCDN_SYNC_INVALID;
    }
    if (length == 3 && memcmp(value, "off", 3) == 0) {
        return SCDN_SYNC_OFF;
    }
    if (length == 6 && memcmp(value, "master", 6) == 0) {
        return SCDN_SYNC_MASTER;
    }
    if (length == 4 && memcmp(value, "node", 4) == 0) {
        return SCDN_SYNC_NODE;
    }
    return SCDN_SYNC_INVALID;
}

const char *
scdn_sync_role_name(scdn_sync_role_t role)
{
    switch (role) {
    case SCDN_SYNC_OFF: return "off";
    case SCDN_SYNC_MASTER: return "master";
    case SCDN_SYNC_NODE: return "node";
    default: return "invalid";
    }
}

int
scdn_sync_valid_id(const unsigned char *value, size_t length)
{
    size_t i;

    if (value == NULL || length == 0 || length > SCDN_SYNC_MAX_ID
        || !scdn_sync_alphanumeric(value[0]))
    {
        return 0;
    }
    for (i = 1; i < length; i++) {
        if (!scdn_sync_alphanumeric(value[i]) && value[i] != '_'
            && value[i] != '-')
        {
            return 0;
        }
    }
    return 1;
}

int
scdn_sync_valid_token(const unsigned char *value, size_t length)
{
    size_t i;

    if (value == NULL || length < SCDN_SYNC_TOKEN_MIN
        || length > SCDN_SYNC_TOKEN_MAX)
    {
        return 0;
    }
    for (i = 0; i < length; i++) {
        if (!scdn_sync_alphanumeric(value[i]) && value[i] != '_'
            && value[i] != '-')
        {
            return 0;
        }
    }
    return 1;
}

static int
scdn_sync_hex(unsigned char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

int
scdn_sync_decode_fingerprint(const unsigned char *value, size_t length,
    unsigned char output[32])
{
    size_t i;
    int high, low;

    if (value == NULL || output == NULL || length != 64) {
        return 0;
    }
    for (i = 0; i < 32; i++) {
        high = scdn_sync_hex(value[i * 2]);
        low = scdn_sync_hex(value[i * 2 + 1]);
        if (high < 0 || low < 0) {
            scdn_sync_clear(output, 32);
            return 0;
        }
        output[i] = (unsigned char) ((high << 4) | low);
    }
    return 1;
}

int
scdn_sync_secure_equal(const unsigned char *a, size_t a_length,
    const unsigned char *b, size_t b_length)
{
    size_t i;
    volatile unsigned char difference = 0;

    if (a == NULL || b == NULL || a_length != b_length) {
        return 0;
    }
    for (i = 0; i < a_length; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}

void
scdn_sync_clear(void *value, size_t length)
{
    volatile unsigned char *p = value;

    while (length-- != 0) {
        *p++ = 0;
    }
}
