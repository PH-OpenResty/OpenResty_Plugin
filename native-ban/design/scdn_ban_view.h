/* Read-only shared-view contract v1 (draft), Linux 64-bit little endian. */
#ifndef SCDN_BAN_VIEW_H
#define SCDN_BAN_VIEW_H
#include <stdatomic.h>
#include "scdn_ban_wire.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Ban view v1 requires little endian"
#endif

#define SCDN_BAN_VIEW_VERSION 1u
#define SCDN_BAN_VIEW_PROBES 64u
#define SCDN_BAN_VIEW_RETRIES 3u
#define SCDN_BAN_VIEW_RECORD_WORDS 22u

enum scdn_ban_view_state {
    SCDN_BAN_VIEW_EMPTY=0, SCDN_BAN_VIEW_TOMBSTONE=1,
    SCDN_BAN_VIEW_L7_ACTIVE=2, SCDN_BAN_VIEW_L3_ACTIVE=3,
    SCDN_BAN_VIEW_L7_FALLBACK=4
};
enum scdn_ban_scope_kind { SCDN_BAN_SCOPE_NODE=0, SCDN_BAN_SCOPE_SITE=1 };

/* Canonical byte key, zero-padded scope; no truncated hash identity. */
typedef struct {
    uint8_t family, scope_kind;
    uint16_t scope_bytes;
    uint32_t reserved;
    uint8_t address[16], scope[SCDN_BAN_SCOPE_MAX];
} scdn_ban_view_key;

typedef struct {
    scdn_ban_view_key key;
    uint8_t ban_id[16];
    uint64_t expires_boot_ns, policy_generation, source_wal_seq;
    uint32_t state;
    uint16_t requested_layer, applied_layer;
    uint32_t flags, reserved;
} scdn_ban_view_record;

/* Atomic words avoid data races even if a writer reuses an old bank while
 * a reader is paused. Decode a stable copy into scdn_ban_view_record. */
typedef struct {
    _Alignas(64) _Atomic uint64_t commit_word;
    uint8_t reserved[56];
    _Atomic uint64_t bank[2][SCDN_BAN_VIEW_RECORD_WORDS];
} scdn_ban_view_slot;

typedef struct {
    _Alignas(64) uint8_t magic[8];      /* ASCII SBNVIEW1 */
    uint32_t version, header_bytes;
    uint64_t file_bytes;
    uint8_t view_id[16], boot_id[16];
    _Atomic uint64_t committed_wal_seq, policy_generation, heartbeat_boot_ns;
    uint8_t node_id[16];
    uint64_t l7_offset;
    uint32_t l7_slots, l7_max_active;
    uint64_t l3_offset;
    uint32_t l3_slots, l3_max_active;
    uint8_t hash_seed[16], reserved[112];
} scdn_ban_view_header;

_Static_assert(sizeof(uintptr_t)==8,"64-bit view required");
_Static_assert(ATOMIC_LLONG_LOCK_FREE==2,"lock-free 64-bit atomics required");
_Static_assert(sizeof(_Atomic uint64_t)==8,"atomic word ABI");
_Static_assert(sizeof(scdn_ban_view_key)==120,"view key ABI");
_Static_assert(sizeof(scdn_ban_view_record)==176,"view record ABI");
_Static_assert(sizeof(scdn_ban_view_slot)==448,"view slot ABI");
_Static_assert(sizeof(scdn_ban_view_header)==256,"view header ABI");
_Static_assert(offsetof(scdn_ban_view_header,l7_offset)==96,"view table offset");
#endif
