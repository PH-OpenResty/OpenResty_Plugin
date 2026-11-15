/* Design contract v1 (draft). No transport or enforcement implementation. */
#ifndef SCDN_BAN_WIRE_H
#define SCDN_BAN_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define SCDN_BAN_WIRE_VERSION 1u
#define SCDN_BAN_FRAME_MAX 8192u
#define SCDN_BAN_SCOPE_MAX 96u
#define SCDN_BAN_REASON_MAX 64u
#define SCDN_BAN_FLAG_JSON 1u

enum scdn_ban_message {
    SCDN_BAN_HELLO=1, SCDN_BAN_HELLO_ACK=2,
    SCDN_BAN_SECURITY_EVENT=3, SCDN_BAN_EVENT_ACK=4,
    SCDN_BAN_VIEW_OFFER=5, SCDN_BAN_VIEW_ACK=6,
    SCDN_BAN_QUERY=7, SCDN_BAN_QUERY_REPLY=8,
    SCDN_BAN_UNBAN=9, SCDN_BAN_ERROR=10,
    SCDN_BAN_PING=11, SCDN_BAN_PONG=12
};

enum scdn_ban_event_source {
    SCDN_BAN_WAF_DENY=1, SCDN_BAN_CC_CONFIRMED=2,
    SCDN_BAN_L7_HIT=3
};

enum scdn_ban_layer { SCDN_BAN_NONE=0, SCDN_BAN_L3=3, SCDN_BAN_L7=7 };

enum scdn_ban_result {
    SCDN_BAN_REGISTERED=0, SCDN_BAN_RECEIVED=1,
    SCDN_BAN_DURABLE_PENDING=2, SCDN_BAN_APPLIED_DURABLE=3,
    SCDN_BAN_APPLY_FAILED=4, SCDN_BAN_STALE=5,
    SCDN_BAN_BACKPRESSURE=6, SCDN_BAN_NEED_VIEW=7,
    SCDN_BAN_NO_ACTION_DURABLE=8
};

enum scdn_ban_ack_flag {
    SCDN_BAN_ACK_VIEW_READY=1u<<0,
    SCDN_BAN_ACK_KERNEL_CONFIRMED=1u<<1,
    SCDN_BAN_ACK_EVENT_LOG_DURABLE=1u<<2,
    SCDN_BAN_ACK_IP_LOG_DURABLE=1u<<3
};

/* Integers ending in _le are encoded little endian. IDs and IPs are bytes.
 * Decode untrusted frames into aligned storage; do not cast socket buffers. */
typedef struct {
    uint8_t magic[4];                 /* ASCII SBN1 */
    uint16_t version_le, type_le;
    uint32_t frame_bytes_le, flags_le;
    uint8_t producer_id[16];
    uint64_t producer_seq_le;
    uint8_t event_id[16];
    uint64_t reserved_le;
} scdn_ban_frame_header;

typedef struct {
    uint8_t instance_id[16], boot_id[16], cycle_id[16];
    uint32_t worker_slot_le, expected_workers_le, role_le, namespace_fds_le;
} scdn_ban_hello;

typedef struct {
    uint8_t agent_id[16], boot_id[16];
    uint64_t durable_producer_seq_le, policy_generation_le, view_generation_le;
    uint32_t result_le, flags_le;
} scdn_ban_hello_ack;

typedef struct {
    uint8_t boot_id[16], instance_id[16], request_id[16], observed_ban_id[16];
    uint64_t observed_boot_ns_le, source_policy_generation_le;
    uint8_t family, source;           /* family is 4 or 6 */
    uint16_t scope_bytes_le, reason_bytes_le, reserved16_le;
    uint64_t reserved64_le;
    uint8_t address[16];              /* IPv4: first 12 bytes zero */
    uint8_t scope[SCDN_BAN_SCOPE_MAX];
    uint8_t reason[SCDN_BAN_REASON_MAX];
} scdn_ban_security_event;

typedef struct {
    uint8_t ban_id[16];
    uint64_t wal_seq_le, view_generation_le, expires_boot_ns_le, decision_boot_ns_le;
    uint32_t result_le;
    uint16_t requested_layer_le, applied_layer_le;
    uint32_t flags_le, error_code_le;
} scdn_ban_ack;

typedef struct {
    uint8_t view_id[16], boot_id[16];
    uint64_t view_generation_le, file_bytes_le;
    uint32_t layout_version_le, descriptor_count_le;
    uint64_t reserved_le;
} scdn_ban_view_offer;

typedef struct {
    uint8_t view_id[16];
    uint64_t view_generation_le;
    uint32_t result_le, reserved_le;
} scdn_ban_view_ack;

_Static_assert(sizeof(scdn_ban_frame_header)==64,"frame header ABI");
_Static_assert(offsetof(scdn_ban_frame_header,producer_seq_le)==32,"sequence offset");
_Static_assert(sizeof(scdn_ban_hello)==64,"hello ABI");
_Static_assert(sizeof(scdn_ban_hello_ack)==64,"hello ack ABI");
_Static_assert(sizeof(scdn_ban_security_event)==272,"event ABI");
_Static_assert(offsetof(scdn_ban_security_event,address)==96,"address offset");
_Static_assert(offsetof(scdn_ban_security_event,scope)==112,"scope offset");
_Static_assert(sizeof(scdn_ban_ack)==64,"ack ABI");
_Static_assert(sizeof(scdn_ban_view_offer)==64,"view offer ABI");
_Static_assert(sizeof(scdn_ban_view_ack)==32,"view ack ABI");

#endif
