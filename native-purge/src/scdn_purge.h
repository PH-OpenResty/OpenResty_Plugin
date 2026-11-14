#ifndef SCDN_PURGE_H
#define SCDN_PURGE_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <sys/file.h>

#if !(NGX_THREADS) || NGX_PTR_SIZE != 8
#error "scdn_purge requires a 64-bit nginx with --with-threads"
#endif

#define SCDN_PURGE_BUCKETS 4096
#define SCDN_PURGE_VERSION "0.1.0"
#define SCDN_PURGE_BATCH 256
#define SCDN_PURGE_KEY 4096
#define SCDN_PURGE_SCOPE 256
#define SCDN_PURGE_BODY (1024 * 1024)
#define SCDN_PURGE_PREFIXES 128
#define SCDN_PURGE_JOURNAL (64 * 1024 * 1024)

typedef struct scdn_purge_node_s scdn_purge_node_t;
struct scdn_purge_node_s {
    scdn_purge_node_t *next, *prefix_next, *prefixes;
    uint64_t epoch;
    uint32_t hash;
    uint16_t scope_length, key_length, prefix_count;
    u_char mode;
    u_char bytes[];
};

typedef struct {
    ngx_uint_t format, nodes;
    ngx_atomic_t sequence;
    uint64_t all_epoch, journal_offset, journal_inode;
    ngx_atomic_t batches, compacted;
    u_char identity[16], identity_hex[33];
    scdn_purge_node_t *buckets[SCDN_PURGE_BUCKETS];
} scdn_purge_shared_t;

typedef struct {
    u_char mode;
    ngx_str_t scope, key;
    scdn_purge_node_t *node;
} scdn_purge_operation_t;

typedef struct {
    ngx_shm_zone_t *zone;
    ngx_slab_pool_t *slab;
    scdn_purge_shared_t *shared;
    ngx_thread_pool_t *threads;
    ngx_str_t journal, token_file, token;
    ngx_uint_t lru_entries;
    size_t checkpoint;
    ngx_flag_t allow_all;
    int owner_fd;
    ngx_array_t locations;
} scdn_purge_main_t;

typedef struct {
    ngx_http_complex_value_t scope, key,resource;
    ngx_flag_t configured;
    ngx_flag_t has_resource;
    ngx_uint_t api;
} scdn_purge_location_t;

typedef struct {
    scdn_purge_main_t *main;
    ngx_http_request_t *request;
    scdn_purge_operation_t operations[SCDN_PURGE_BATCH];
    ngx_uint_t count, status;
    uint64_t sequence;
    const char *error;
    scdn_purge_node_t *created[SCDN_PURGE_BATCH*2];
    ngx_uint_t created_count;
} scdn_purge_job_t;

extern ngx_module_t ngx_http_scdn_purge_module;
ngx_int_t scdn_purge_zone_init(ngx_shm_zone_t *zone, void *previous);
uint32_t scdn_purge_hash(u_char mode, const ngx_str_t *scope, const ngx_str_t *key);
uint64_t scdn_purge_epoch(scdn_purge_main_t *main, const ngx_str_t *scope,
    const ngx_str_t *key, uint64_t *sequence);
void scdn_purge_commit(void *data, ngx_log_t *log);

#endif
