#include "scdn_edge.h"
#include <ngx_http_ssl_module.h>
#if (NGX_SCDN_API)
#include "scdn_api.h"
#endif

static void *edge_main(ngx_conf_t *cf);
static void *edge_server(ngx_conf_t *cf);
static void *edge_location(ngx_conf_t *cf);
static char *edge_merge_server(ngx_conf_t *cf, void *parent, void *child);
static char *edge_merge_location(ngx_conf_t *cf, void *parent, void *child);
static char *edge_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static char *edge_metrics_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static ngx_int_t edge_preconfiguration(ngx_conf_t *cf);
static ngx_int_t edge_postconfiguration(ngx_conf_t *cf);
static ngx_int_t edge_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t edge_access(ngx_http_request_t *r);

static ngx_command_t edge_commands[] = {
    { ngx_string("scdn_edge"), NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(scdn_edge_server_t, enabled), NULL },
    { ngx_string("scdn_edge_tls"), NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(scdn_edge_server_t, tls), NULL },
    { ngx_string("scdn_edge_proxy_location"), NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(scdn_edge_server_t, proxy_location), NULL },
    { ngx_string("scdn_edge_zone"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      edge_zone, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_edge_metrics"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      edge_metrics_directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    ngx_null_command
};

static ngx_http_module_t edge_context = {
    edge_preconfiguration, edge_postconfiguration, edge_main, NULL,
    edge_server, edge_merge_server, edge_location, edge_merge_location
};

ngx_module_t ngx_http_scdn_edge_module = {
    NGX_MODULE_V1, &edge_context, edge_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

static void *
edge_main(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(scdn_edge_main_t));
}

static void *
edge_server(ngx_conf_t *cf)
{
    scdn_edge_server_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf != NULL) { conf->enabled = NGX_CONF_UNSET; conf->tls = NGX_CONF_UNSET; }
    return conf;
}

static void *
edge_location(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(scdn_edge_location_t));
}

static char *
edge_merge_server(ngx_conf_t *cf, void *parent, void *child)
{
    scdn_edge_server_t *previous = parent, *conf = child;
    (void) cf;
    ngx_conf_merge_value(conf->enabled, previous->enabled, 0);
    ngx_conf_merge_value(conf->tls, previous->tls, 0);
    ngx_conf_merge_str_value(conf->proxy_location, previous->proxy_location, "@scdn_edge_proxy");
    if (conf->proxy_location.len == 0 || conf->proxy_location.data[0] != '@'
        || (conf->tls && !conf->enabled))
    {
        return "scdn_edge requires a named proxy location and TLS requires scdn_edge on";
    }
    return NGX_CONF_OK;
}

static char *
edge_merge_location(ngx_conf_t *cf, void *parent, void *child)
{
    scdn_edge_location_t *conf = child;
    ngx_http_core_loc_conf_t *location;
    (void) parent;
    location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (conf->metrics && location->handler != scdn_edge_metrics) {
        return "scdn_edge_metrics conflicts with another content handler";
    }
    return NGX_CONF_OK;
}

static char *
edge_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    scdn_edge_main_t *conf = data;
    ngx_str_t *values = cf->args->elts;
    ssize_t size = ngx_parse_size(&values[2]);
    (void) cmd;
    if (conf->zone != NULL) { return "is duplicate"; }
    if (size < (ssize_t) (sizeof(scdn_edge_shared_t) + 16 * ngx_pagesize)
        || size > 64 * 1024 * 1024)
    { return "requires enough shared memory (normally 2m), up to 64m"; }
    conf->zone = ngx_shared_memory_add(cf, &values[1], size, &ngx_http_scdn_edge_module);
    if (conf->zone == NULL) { return NGX_CONF_ERROR; }
    conf->zone->data = conf;
    conf->zone->init = scdn_edge_zone_init;
    return NGX_CONF_OK;
}

static char *
edge_metrics_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    scdn_edge_location_t *conf = data;
    ngx_http_core_loc_conf_t *location;
    (void) cmd;
    location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (conf->metrics || location->handler != NULL) { return "conflicts with a content handler"; }
    conf->metrics = 1; location->handler = scdn_edge_metrics;
    return NGX_CONF_OK;
}

static void
edge_cleanup(void *data)
{
    scdn_edge_request_t *request = data;
    scdn_config_release(request->snapshot);
}

scdn_edge_request_t *
scdn_edge_request(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t *cleanup;
    scdn_edge_request_t *request, *parent;
    scdn_edge_server_t *server;
    scdn_config_route_t *best = NULL;
    ngx_uint_t i;

    for (cleanup = r->pool->cleanup; cleanup != NULL; cleanup = cleanup->next) {
        if (cleanup->handler == edge_cleanup
            && ((scdn_edge_request_t *) cleanup->data)->owner == r)
        { return cleanup->data; }
    }
    server = ngx_http_get_module_srv_conf(r, ngx_http_scdn_edge_module);
    if (!server->enabled) { return NULL; }
    cleanup = ngx_pool_cleanup_add(r->pool, sizeof(*request));
    if (cleanup == NULL) { return NULL; }
    request = cleanup->data;
    ngx_memzero(request, sizeof(*request));
    request->owner = r; cleanup->handler = edge_cleanup;
    parent = r != r->main ? scdn_edge_request(r->main) : NULL;
    if (parent != NULL && parent->snapshot != NULL) {
        request->snapshot = parent->snapshot; request->snapshot->refs++;
    } else { request->snapshot = scdn_config_acquire(); }
    request->site = scdn_config_lookup(request->snapshot, &r->headers_in.server);
    if (request->site == NULL) { return request; }
    request->counter = scdn_edge_counter(r, &request->site->id);
    request->upstream = request->site->upstream;
    request->cache = request->site->cache;
    request->origin_host = request->site->origin_host;
    for (i = 0; i < request->site->route_count; i++) {
        scdn_config_route_t *route = &request->site->routes[i];
        if (r->uri.len >= route->prefix.len
            && ngx_memcmp(r->uri.data, route->prefix.data, route->prefix.len) == 0
            && (best == NULL || best->prefix.len < route->prefix.len)) { best = route; }
    }
    if (best != NULL) {
        request->upstream = best->upstream; request->cache = best->cache;
        if (best->origin_host.len) { request->origin_host = best->origin_host; }
    }
    return request;
}

static ngx_int_t
edge_access(ngx_http_request_t *r)
{
    scdn_edge_server_t *server;
    scdn_edge_request_t *request;
    ngx_str_t *location;
#if (NGX_SCDN_API)
    ngx_int_t rc;
#endif
    server = ngx_http_get_module_srv_conf(r, ngx_http_scdn_edge_module);
    if (!server->enabled) { return NGX_DECLINED; }
    request = scdn_edge_request(r);
    if (request == NULL || request->snapshot == NULL) { return NGX_HTTP_SERVICE_UNAVAILABLE; }
    if (request->site == NULL || !request->site->enabled) { return NGX_HTTP_FORBIDDEN; }
    if (!request->routed && request->upstream.len != 0) {
        location = &server->proxy_location;
#if (NGX_SCDN_API)
        rc = ngx_http_scdn_api_prepare(r);
        if (rc != NGX_DECLINED) { return rc; }
        location = ngx_http_scdn_api_location(r, location);
#endif
        request->routed = 1;
        (void) ngx_http_named_location(r, location);
        /* Named redirects take a request reference, as in try_files. */
        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }
    return NGX_DECLINED;
}

static ngx_int_t
edge_preconfiguration(ngx_conf_t *cf)
{
    static ngx_str_t names[] = {
        ngx_string("scdn_edge_site"), ngx_string("scdn_edge_upstream"),
        ngx_string("scdn_edge_root"), ngx_string("scdn_edge_cache"),
        ngx_string("scdn_edge_revision"), ngx_string("scdn_edge_origin_host"),
        ngx_string("scdn_edge_origin_sni"), ngx_string("scdn_edge_grpc_upstream")
    };
    ngx_http_variable_t *variable;
    ngx_uint_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        variable = ngx_http_add_variable(cf, &names[i], NGX_HTTP_VAR_NOCACHEABLE);
        if (variable == NULL) { return NGX_ERROR; }
        variable->get_handler = edge_variable; variable->data = i;
    }
    return NGX_OK;
}

static ngx_int_t
edge_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    scdn_edge_request_t *request = scdn_edge_request(r);
    ngx_str_t value = ngx_null_string;
    size_t start, end;
    u_char *out;
    if (request == NULL || request->site == NULL) { v->not_found = 1; return NGX_OK; }
    if (data == 0) { value = request->site->id; }
    else if (data == 1) { value = request->upstream; }
    else if (data == 2) { value = request->site->root; }
    else if (data == 4) { value.data = request->snapshot->revision; value.len = 64; }
    else if (data == 5 || data == 6) {
        if (request->origin_host.len
            && !(request->origin_host.len == 4
                && ngx_memcmp(request->origin_host.data, "auto", 4) == 0)) {
            value = request->origin_host;
        } else if (data == 5 && request->origin_host.len == 0) {
            /* Preserve the existing CDN Host policy unless explicitly changed. */
            value = r->headers_in.server;
        } else if (request->upstream.len > 7) {
            start = request->upstream.data[4] == 's' ? 8 : 7;
            end = request->upstream.len;
            if (data == 6) {
                if (request->upstream.data[start] == '[') {
                    start++;
                    for (end = start; end < request->upstream.len
                         && request->upstream.data[end] != ']'; end++) { }
                } else {
                    for (end = start; end < request->upstream.len
                         && request->upstream.data[end] != ':'; end++) { }
                }
            }
            value.data = request->upstream.data + start; value.len = end - start;
        }
    } else if (data == 7) {
        if (request->upstream.len > 7) {
            value.len = request->upstream.len;
            value.data = ngx_pnalloc(r->pool, value.len);
            if (value.data == NULL) { return NGX_ERROR; }
            start = request->upstream.data[4] == 's' ? 8 : 7;
            out = ngx_cpymem(value.data, start == 8 ? "grpcs://" : "grpc://", start);
            ngx_memcpy(out, request->upstream.data + start, request->upstream.len - start);
        }
    }
    else {
        value = request->cache;
        if (value.len == 4 && ngx_memcmp(value.data, "auto", 4) == 0) {
            if (scdn_edge_tier(r, request)) { ngx_str_set(&value, "l1"); }
            else { ngx_str_set(&value, "l2"); }
        }
    }
    v->data = value.data; v->len = value.len; v->valid = 1;
    v->no_cacheable = 1; v->not_found = 0;
    return NGX_OK;
}

static int
edge_certificate(SSL *ssl, void *data)
{
    scdn_config_snapshot_t *snapshot;
    scdn_config_site_t *site;
    ngx_str_t host;
    const char *name;
    int result = 0, i;
    (void) data;
    name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name == NULL) { return 0; }
    host.data = (u_char *) name; host.len = strlen(name);
    snapshot = scdn_config_acquire();
    site = scdn_config_lookup(snapshot, &host);
    if (site != NULL && site->enabled && site->leaf != NULL
        && X509_cmp_current_time(X509_get0_notAfter(site->leaf)) > 0
        && SSL_use_certificate(ssl, site->leaf) == 1
        && SSL_use_PrivateKey(ssl, site->key) == 1
        && SSL_clear_chain_certs(ssl) == 1)
    {
        result = 1;
        for (i = 0; i < sk_X509_num(site->chain); i++) {
            if (SSL_add1_chain_cert(ssl, sk_X509_value(site->chain, i)) != 1) { result = 0; break; }
        }
    }
    scdn_config_release(snapshot);
    return result;
}

static ngx_int_t
edge_postconfiguration(ngx_conf_t *cf)
{
    scdn_edge_main_t *main;
    scdn_edge_server_t *server;
    ngx_http_core_main_conf_t *core;
    ngx_http_core_srv_conf_t **servers;
    ngx_http_ssl_srv_conf_t *ssl;
    ngx_http_handler_pt *handler;
    ngx_uint_t i;
    main = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_edge_module);
    core = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    servers = core->servers.elts;
    for (i = 0; i < core->servers.nelts; i++) {
        server = servers[i]->ctx->srv_conf[ngx_http_scdn_edge_module.ctx_index];
        if (!server->enabled) { continue; }
        if (main->zone == NULL || !scdn_config_enabled(cf)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "scdn_edge requires scdn_edge_zone and scdn_config_watch");
            return NGX_ERROR;
        }
        if (server->tls) {
            ssl = servers[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
            if (ssl->ssl.ctx == NULL || ssl->certificate_values != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "scdn_edge_tls requires a static bootstrap certificate and its own TLS callback");
                return NGX_ERROR;
            }
            SSL_CTX_set_cert_cb(ssl->ssl.ctx, edge_certificate, NULL);
        }
    }
    handler = ngx_array_push(&core->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (handler == NULL) { return NGX_ERROR; } *handler = edge_access;
    handler = ngx_array_push(&core->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (handler == NULL) { return NGX_ERROR; } *handler = scdn_edge_record;
    return NGX_OK;
}
