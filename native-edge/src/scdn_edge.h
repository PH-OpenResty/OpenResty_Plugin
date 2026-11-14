#ifndef SCDN_EDGE_H
#define SCDN_EDGE_H
#include "scdn_config.h"
#include <ngx_md5.h>

#define SCDN_EDGE_COUNTERS 1024
#define SCDN_EDGE_HOT 4096

typedef struct {
    size_t length;
    u_char id[96];
    ngx_atomic_t requests, bytes, status[6], cache[8];
} scdn_edge_counter_t;

typedef struct {
    u_char digest[16];
    ngx_msec_t start;
    ngx_uint_t hits;
    ngx_flag_t used;
} scdn_edge_hot_t;

typedef struct {
    ngx_uint_t count;
    scdn_edge_counter_t counters[SCDN_EDGE_COUNTERS];
    scdn_edge_hot_t hot[SCDN_EDGE_HOT];
} scdn_edge_shared_t;

typedef struct {
    ngx_shm_zone_t *zone;
    ngx_slab_pool_t *slab;
    scdn_edge_shared_t *shared;
} scdn_edge_main_t;

typedef struct {
    ngx_flag_t enabled, tls;
    ngx_str_t proxy_location;
} scdn_edge_server_t;

typedef struct {
    ngx_flag_t metrics;
} scdn_edge_location_t;

typedef struct {
    ngx_http_request_t *owner;
    scdn_config_snapshot_t *snapshot;
    scdn_config_site_t *site;
    scdn_edge_counter_t *counter;
    ngx_str_t upstream, cache;
    ngx_flag_t routed, recorded, tier_done, tier_hot;
} scdn_edge_request_t;

extern ngx_module_t ngx_http_scdn_edge_module;
scdn_edge_request_t *scdn_edge_request(ngx_http_request_t *r);
ngx_int_t scdn_edge_zone_init(ngx_shm_zone_t *zone, void *old);
ngx_int_t scdn_edge_record(ngx_http_request_t *r);
ngx_int_t scdn_edge_metrics(ngx_http_request_t *r);
ngx_flag_t scdn_edge_tier(ngx_http_request_t *r, scdn_edge_request_t *request);
scdn_edge_counter_t *scdn_edge_counter(ngx_http_request_t *r, ngx_str_t *id);
#endif
