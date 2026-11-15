#include "scdn_sync_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    unsigned char bytes[160], fingerprint[32], encoded[64];
    size_t i;

    assert(scdn_sync_parse_role((const unsigned char *) "master", 6)
           == SCDN_SYNC_MASTER);
    assert(scdn_sync_parse_role((const unsigned char *) "node", 4)
           == SCDN_SYNC_NODE);
    assert(scdn_sync_parse_role((const unsigned char *) "off", 3)
           == SCDN_SYNC_OFF);
    assert(scdn_sync_parse_role((const unsigned char *) "Master", 6)
           == SCDN_SYNC_INVALID);
    assert(scdn_sync_parse_role(NULL, 6) == SCDN_SYNC_INVALID);
    assert(strcmp(scdn_sync_role_name(SCDN_SYNC_NODE), "node") == 0);
    memset(bytes, 'a', sizeof(bytes));
    assert(scdn_sync_valid_id(bytes, SCDN_SYNC_MAX_ID));
    assert(!scdn_sync_valid_id(bytes, SCDN_SYNC_MAX_ID + 1));
    assert(!scdn_sync_valid_id(bytes, 0));
    for (i = 0; i < 256; i++) {
        bytes[0] = (unsigned char) i;
        assert(scdn_sync_valid_id(bytes, 1)
               == ((i >= 'a' && i <= 'z') || (i >= 'A' && i <= 'Z')
                   || (i >= '0' && i <= '9')));
    }
    memset(bytes, 'a', sizeof(bytes));
    bytes[1] = '_';
    bytes[2] = '-';
    assert(scdn_sync_valid_id(bytes, 3));
    bytes[1] = '/';
    assert(!scdn_sync_valid_id(bytes, 3));
    memset(bytes, 'a', sizeof(bytes));
    assert(scdn_sync_valid_token(bytes, SCDN_SYNC_TOKEN_MIN));
    assert(scdn_sync_valid_token(bytes, SCDN_SYNC_TOKEN_MAX));
    assert(!scdn_sync_valid_token(bytes, SCDN_SYNC_TOKEN_MIN - 1));
    assert(!scdn_sync_valid_token(bytes, SCDN_SYNC_TOKEN_MAX + 1));
    bytes[5] = 0;
    assert(!scdn_sync_valid_token(bytes, SCDN_SYNC_TOKEN_MIN));
    memset(encoded, 'a', sizeof(encoded));
    assert(scdn_sync_decode_fingerprint(encoded, sizeof(encoded), fingerprint));
    for (i = 0; i < sizeof(fingerprint); i++) {
        assert(fingerprint[i] == 0xaa);
    }
    encoded[63] = 'Z';
    assert(!scdn_sync_decode_fingerprint(encoded, sizeof(encoded), fingerprint));
    for (i = 0; i < sizeof(fingerprint); i++) {
        assert(fingerprint[i] == 0);
    }
    memset(bytes, 'a', sizeof(bytes));
    assert(scdn_sync_secure_equal(bytes, 64, bytes + 64, 64));
    bytes[159] = 'b';
    assert(!scdn_sync_secure_equal(bytes, 64, bytes + 96, 64));
    assert(!scdn_sync_secure_equal(bytes, 63, bytes, 64));
    scdn_sync_clear(bytes, sizeof(bytes));
    for (i = 0; i < sizeof(bytes); i++) {
        assert(bytes[i] == 0);
    }
    puts("native core boundary checks passed");
    return 0;
}
