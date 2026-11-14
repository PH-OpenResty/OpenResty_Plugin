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

typedef struct {
    ngx_str_t prefix, upstream, cache;
} scdn_config_route_t;

typedef struct {
    ngx_str_t id, hosts[SCDN_CONFIG_HOSTS], upstream, root, cache;
    ngx_str_t certificate, certificate_key;
    ngx_uint_t host_count, route_count;
    scdn_config_route_t routes[SCDN_CONFIG_ROUTES];
    ngx_flag_t enabled;
    ngx_uint_t tier_hits;
    ngx_msec_t tier_window;
    X509 *leaf;
    STACK_OF(X509) *chain;
    EVP_PKEY *key;
    u_char material_digest[32];
} scdn_config_site_t;

typedef struct {
    ngx_uint_t refs, count;
    scdn_config_site_t sites[SCDN_CONFIG_SITES];
    u_char digest[32], revision[65];
    u_char *source;
    size_t source_size;
} scdn_config_snapshot_t;

extern ngx_module_t ngx_http_scdn_config_module;

/* Loader only runs at startup or on a worker's dedicated thread-pool task. */
scdn_config_snapshot_t *scdn_config_load(const char *path, const char **error);
scdn_config_snapshot_t *scdn_config_load_cached(const char *path,
    const char **error, const scdn_config_snapshot_t *cache);
void scdn_config_destroy(scdn_config_snapshot_t *snapshot);
scdn_config_snapshot_t *scdn_config_acquire(void);
void scdn_config_release(scdn_config_snapshot_t *snapshot);
scdn_config_site_t *scdn_config_lookup(scdn_config_snapshot_t *snapshot,
    const ngx_str_t *host);
ngx_flag_t scdn_config_local(ngx_http_request_t *r);
ngx_flag_t scdn_config_enabled(ngx_conf_t *cf);

#endif
