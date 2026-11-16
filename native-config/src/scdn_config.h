#ifndef SCDN_CONFIG_H
#define SCDN_CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/ssl.h>

#define SCDN_CONFIG_SITES 256
#define SCDN_CONFIG_HOSTS 32
#define SCDN_CONFIG_ROUTES 32
#define SCDN_CONFIG_WORKERS 128
#define SCDN_CONFIG_BYTES (4 * 1024 * 1024)
#define SCDN_CONFIG_HEADERS 8
#define SCDN_CONFIG_PENDING_BYTES 184
#define SCDN_CONFIG_WAF_GROUPS 16

typedef struct {
    ngx_flag_t waf, rate_limit;
    ngx_uint_t threshold, group_count, rate, burst;
    ngx_str_t groups[SCDN_CONFIG_WAF_GROUPS];
} scdn_config_security_t;

typedef struct {
    ngx_str_t name, value;
} scdn_config_header_t;

typedef struct {
    ngx_uint_t count;
    ngx_flag_t configured;
    scdn_config_header_t fields[SCDN_CONFIG_HEADERS];
} scdn_config_headers_t;

typedef struct {
    ngx_str_t prefix, upstream, cache, origin_host;
    scdn_config_headers_t cache_request_headers;
    ngx_flag_t cache_headers;
} scdn_config_route_t;

typedef struct {
    ngx_str_t id, hosts[SCDN_CONFIG_HOSTS], upstream, root, cache, origin_host;
    ngx_str_t certificate, certificate_key;
    ngx_uint_t host_count, route_count;
    scdn_config_route_t routes[SCDN_CONFIG_ROUTES];
    ngx_flag_t enabled;
    scdn_config_headers_t cache_request_headers;
    ngx_flag_t cache_headers;
    ngx_uint_t tier_hits;
    ngx_msec_t tier_window;
    scdn_config_security_t security;
    X509 *leaf;
    STACK_OF(X509) *chain;
    EVP_PKEY *key;
    u_char material_digest[32];
} scdn_config_site_t;

typedef struct {
    ngx_str_t host;
    ngx_uint_t site;
} scdn_config_host_t;

typedef struct {
    ngx_uint_t refs, count;
    scdn_config_site_t *sites;
    scdn_config_host_t *hosts;
    ngx_uint_t host_count;
    u_char digest[32], source_digest[32], revision[65];
    u_char *source;
    size_t source_size;
} scdn_config_snapshot_t;

extern ngx_module_t ngx_http_scdn_config_module;

/* Loader only runs at startup or on a worker's dedicated thread-pool task. */
scdn_config_snapshot_t *scdn_config_load(const char *path, const char **error);
scdn_config_snapshot_t *scdn_config_load_cached(const char *path,
    const char **error, const scdn_config_snapshot_t *cache);
int scdn_config_matches(const char *path, const scdn_config_snapshot_t *cache);
void scdn_config_destroy(scdn_config_snapshot_t *snapshot);
scdn_config_snapshot_t *scdn_config_acquire(void);
void scdn_config_release(scdn_config_snapshot_t *snapshot);
scdn_config_site_t *scdn_config_lookup(scdn_config_snapshot_t *snapshot,
    const ngx_str_t *host);
ngx_flag_t scdn_config_local(ngx_http_request_t *r);
ngx_flag_t scdn_config_enabled(ngx_conf_t *cf);
int scdn_config_recover(const char *directory);
int scdn_config_recover_locked(int directory, int finalize);

#endif
