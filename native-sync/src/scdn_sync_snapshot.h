#ifndef SCDN_SYNC_SNAPSHOT_H
#define SCDN_SYNC_SNAPSHOT_H
#include "scdn_config.h"

scdn_config_snapshot_t *scdn_sync_snapshot_load(const char *path, const char **error);
int scdn_sync_snapshot_matches(const char *path, const scdn_config_snapshot_t *cache);
void scdn_sync_snapshot_destroy(scdn_config_snapshot_t *snapshot);
/* Canonical site configuration; only certificate paths are relocated. */
u_char *scdn_sync_snapshot_export(scdn_config_snapshot_t *snapshot,
    const char *certificate_directory, size_t *size);
int scdn_sync_safe_open(const char *path, int directory);
u_char *scdn_sync_read_file(const char *path, size_t limit, size_t *length, int private_file);
int scdn_sync_write_file(int directory, const char *name, const void *bytes, size_t length);
void scdn_sync_digest(const void *bytes, size_t length, u_char digest[32]);
int scdn_sync_recover(const char *directory);
int scdn_sync_recover_locked(int directory, int finalize);
#endif
