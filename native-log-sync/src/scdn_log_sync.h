#ifndef SCDN_LOG_SYNC_H
#define SCDN_LOG_SYNC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
  uint64_t confirmed, pending, files, sent_requests;
  int error;
} scdn_log_sync_result;
/* All filesystem and HTTP work is called from the private sender thread. */
void *scdn_log_sync_create(const char *path, int *error);
int scdn_log_sync_cycle(void *engine, scdn_log_sync_result *result);
void scdn_log_sync_destroy(void *engine);
const char *scdn_log_sync_error(int error);
typedef struct {
  uint64_t confirmed, pending, files, sent_requests, cycles, failures,
      sample_failures;
  int error, running;
} scdn_log_sync_status;
void *scdn_log_sync_start(const char *path, unsigned interval_ms);
void scdn_log_sync_stop(void *service);
void scdn_log_sync_status_read(void *service, scdn_log_sync_status *status);
#ifdef __cplusplus
}
#endif
#endif
