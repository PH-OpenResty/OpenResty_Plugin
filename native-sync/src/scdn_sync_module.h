#ifndef SCDN_SYNC_MODULE_H
#define SCDN_SYNC_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include "scdn_sync_core.h"

typedef struct {
    ngx_str_t id, scope;
    u_char fingerprint[32];
} ngx_http_scdn_peer_t;

typedef struct {
    ngx_http_conf_ctx_t *context;
    ngx_uint_t mode;
} ngx_http_scdn_endpoint_t;

typedef struct {
    ngx_str_t scope, url, connect;
} scdn_sync_cache_site_t;

typedef struct {
    ngx_str_t directory, master, ca, certificate, key;
    ngx_str_t purge_socket, purge_path, purge_token_file, purge_token, local_ca;
    ngx_array_t sites;
    ngx_thread_pool_t *threads;
    ngx_msec_t poll;
    ngx_flag_t allow_all;
    ngx_uint_t configured;
} scdn_sync_tasks_conf_t;

typedef struct {
    scdn_sync_role_t role;
    ngx_flag_t role_set;
    ngx_str_t id, scope, token_file, token;
    ngx_array_t peers, endpoints;
    scdn_sync_tasks_conf_t cache;
} ngx_http_scdn_main_conf_t;

extern ngx_module_t ngx_http_scdn_sync_module;
ngx_int_t scdn_sync_load_token(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *token);
ngx_int_t ngx_http_scdn_reply(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body);
ngx_int_t ngx_http_scdn_error(ngx_http_request_t *r, ngx_uint_t status,
    const char *code);
ngx_int_t ngx_http_scdn_header(ngx_http_request_t *r, const char *key,
    const char *value);
char *scdn_sync_tasks_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t scdn_sync_tasks_configure(ngx_conf_t *cf,
    ngx_http_scdn_main_conf_t *conf);
ngx_int_t scdn_sync_tasks_process(ngx_cycle_t *cycle);
ngx_int_t scdn_sync_tasks_handler(ngx_http_request_t *r,
    ngx_http_scdn_main_conf_t *conf, ngx_http_scdn_peer_t *peer,
    ngx_flag_t exchange);

#endif
