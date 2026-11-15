/* v2 draft full-snapshot object layout; no transport or BPF implementation. */
#ifndef SCDN_BAN_CLUSTER_H
#define SCDN_BAN_CLUSTER_H
#include <stddef.h>
#include <stdint.h>

#define SCDN_BAN_CLUSTER_VERSION 2u
#define SCDN_BAN_CLUSTER_RECORD_BYTES 160u
#define SCDN_BAN_CLUSTER_MANIFEST_BYTES 192u
#define SCDN_BAN_CLUSTER_MAX_IPS 1048576u

/* Bytes 0..127 are signed with Ed25519, including the complete object digest.
 * Read from bounded byte buffers into aligned storage; validate all fields.
 * signature_key_id selects a key from local trust, never from this object. */
typedef struct {
    uint32_t version_le, header_bytes_le, record_bytes_le, record_count_le;
    uint8_t cluster_id[16], authority_epoch[16];
    uint64_t revision_le, generated_utc_ms_le, membership_revision_le;
    uint8_t records_sha256[32], signature_key_id[24], signature[64];
} scdn_ban_cluster_manifest;

/* Canonical order: family then normalized address, unique IP per snapshot.
 * IPv4 uses address[0..3], address[4..15]=0; IPv4-mapped IPv6 normalizes to v4.
 * source_device is the first accepted source; extra sources remain in audit.
 * imported records are never fed back as new local security decisions. */
typedef struct {
    uint8_t address[16], ban_id[16], source_device[16];
    uint64_t expires_utc_ms_le, decided_utc_ms_le, policy_generation_le;
    uint32_t family_le, flags_le;
    uint8_t reason[64], reserved[16];
} scdn_ban_cluster_record;

enum scdn_ban_cluster_phase {
    SCDN_BAN_CLUSTER_DOWNLOADED = 1, SCDN_BAN_CLUSTER_VALIDATED = 2,
    SCDN_BAN_CLUSTER_DURABLE = 3, SCDN_BAN_CLUSTER_APPLYING = 4,
    SCDN_BAN_CLUSTER_APPLIED = 5, SCDN_BAN_CLUSTER_APPLY_FAILED = 6,
    SCDN_BAN_CLUSTER_CLOCK_UNCERTAIN = 7
};

_Static_assert(sizeof(scdn_ban_cluster_manifest) == 192, "cluster manifest ABI");
_Static_assert(offsetof(scdn_ban_cluster_manifest, signature) == 128, "signed prefix");
_Static_assert(sizeof(scdn_ban_cluster_record) == 160, "cluster record ABI");
_Static_assert(offsetof(scdn_ban_cluster_record, expires_utc_ms_le) == 48, "UTC expiry");
#endif
