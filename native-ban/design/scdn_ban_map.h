/* Kernel/user Map layout contract v1 (draft); stable-width fields only. */
#ifndef SCDN_BAN_MAP_H
#define SCDN_BAN_MAP_H
#include <stddef.h>
#include <stdint.h>

typedef struct { uint32_t address_be; } scdn_ban_ipv4_key;
typedef struct { uint8_t address[16]; } scdn_ban_ipv6_key;

/* Same-host native endian scalars; address bytes are network order.
 * Only the Agent writes the active-ban map. Packet code never renews TTL. */
typedef struct {
    uint64_t expires_boot_ns;
    uint8_t ban_id[16];
    uint64_t policy_generation;
} scdn_ban_map_value;

typedef struct {
    uint32_t destination_be;
    uint16_t port_be;
    uint8_t protocol, reserved;
} scdn_ban_service4_key;

typedef struct {
    uint8_t destination[16];
    uint16_t port_be;
    uint8_t protocol, reserved;
} scdn_ban_service6_key;

typedef struct { uint64_t packets, bytes; } scdn_ban_counter;

_Static_assert(sizeof(scdn_ban_ipv4_key)==4,"IPv4 map key ABI");
_Static_assert(sizeof(scdn_ban_ipv6_key)==16,"IPv6 map key ABI");
_Static_assert(sizeof(scdn_ban_map_value)==32,"map value ABI");
_Static_assert(offsetof(scdn_ban_map_value,ban_id)==8,"map ban ID offset");
_Static_assert(sizeof(scdn_ban_service4_key)==8,"IPv4 service key ABI");
_Static_assert(sizeof(scdn_ban_service6_key)==20,"IPv6 service key ABI");
_Static_assert(sizeof(scdn_ban_counter)==16,"counter ABI");
#endif
