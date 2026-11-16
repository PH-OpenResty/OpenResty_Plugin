#ifndef SCDN_BAN_COMMON_H
#define SCDN_BAN_COMMON_H
#include <stddef.h>
#include <stdint.h>
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "native-ban shared ABI requires little endian"
#endif
#define BAN_CAPACITY 4096u
#define BAN_SLOTS 8192u
#define BAN_MAX_FRAME (4u * 1024u * 1024u)
#define BAN_VIEW_MAGIC UINT64_C(0x31574549564e4142)
#define BAN_VERSION 1u
/* One representation everywhere: IPv4 occupies the final four address bytes. */
typedef struct {
  uint32_t family;
  uint8_t address[16];
} ban_address;
typedef struct {
  ban_address ip;
  uint16_t port;
  uint8_t protocol, reserved;
} ban_service;
typedef struct {
  uint64_t deadline;
  uint8_t id[16];
  uint64_t generation;
} ban_kernel_value;
typedef struct {
  ban_address ip;
  char scope[96];
  uint8_t id[16];
  uint64_t deadline, generation;
  uint32_t layer, local_waf;
} ban_record;
#define BAN_WORDS (sizeof(ban_record) / 8)
typedef struct {
  uint64_t commit;
  uint64_t bank[2][BAN_WORDS];
} ban_slot;
typedef struct {
  uint64_t magic;
  uint32_t version, slots;
  uint8_t boot[16];
  uint64_t generation, heartbeat;
  uint8_t hash_key[16];
  uint64_t reserved[3];
  ban_slot table[BAN_SLOTS];
} ban_view;
/* SOCK_SEQPACKET producer protocol. All scalars are native little endian,
 * only same net/time namespace is accepted; JSON is reserved for admin/Sync. */
enum { BAN_HELLO = 1, BAN_EVENT = 2, BAN_ACK = 3, BAN_QUERY = 4 };
enum { BAN_WAF = 1, BAN_CC = 2, BAN_HIT = 3 };
typedef struct {
  uint32_t version, type;
  uint64_t sequence;
  uint8_t producer[16], boot[16], instance[16], request[16], observed[16];
  uint64_t observed_ns, generation;
  ban_address ip;
  uint32_t source;
  char scope[96], reason[64];
} ban_event;
typedef struct {
  uint32_t version, result;
  uint64_t sequence, durable;
} ban_ack;
#ifdef __cplusplus
extern "C" {
#endif
uint64_t ban_now(void);
int ban_uuid(const char *text, uint8_t out[16]);
int ban_address_parse(const char *text, ban_address *out);
int ban_address_socket(int fd, ban_address *out);
uint64_t ban_hash(const void *data, size_t length, const uint8_t seed[16]);
/* 1 matched, 0 clear, -1 unstable/corrupt; one fixed bounded lookup. */
int ban_view_lookup(const ban_view *view, const ban_address *address,
                    const char *scope, uint64_t now, ban_record *out);
int ban_view_write(ban_view *view, const ban_record *record, int remove);
int ban_view_valid(const ban_view *view, size_t bytes, const uint8_t boot[16]);
#ifdef __cplusplus
}
#endif
#endif
