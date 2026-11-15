#include "scdn_api.h"

enum { API_WEB, API_DYNAMIC, API_AI, API_STREAM, API_GRPC, API_WEBSOCKET, API_KINDS };

typedef struct {
    ngx_flag_t enabled, dispatch;
    size_t inspect;
    ngx_msec_t stream_timeout;
    ngx_str_t dynamic_location, ai_location, stream_location;
    ngx_str_t grpc_location, websocket_location;
} api_location_t;

typedef struct {
    ngx_http_request_t *owner;
    ngx_uint_t kind;
    ngx_str_t reason;
    ngx_flag_t headers_done, body_started, prepared, dispatched;
    ngx_flag_t stream, private_request, recorded;
    ngx_http_upstream_conf_t *upstream_conf;
} api_request_t;

typedef struct {
    ngx_atomic_t kinds[API_KINDS], streaming;
} api_shared_t;

typedef struct {
    ngx_shm_zone_t *zone;
    api_shared_t *shared;
} api_main_t;

typedef struct {
    ngx_http_upstream_init_peer_pt original_init;
} api_pool_t;

typedef struct {
    ngx_http_request_t *request;
    void *data;
    ngx_event_get_peer_pt get;
    ngx_event_free_peer_pt free;
    ngx_event_notify_peer_pt notify;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt set_session;
    ngx_event_save_peer_session_pt save_session;
#endif
} api_peer_t;

static ngx_http_output_header_filter_pt api_next_header;
static ngx_http_output_body_filter_pt api_next_body;
static ngx_int_t api_preconfiguration(ngx_conf_t *cf);
static ngx_int_t api_postconfiguration(ngx_conf_t *cf);
static void *api_main(ngx_conf_t *cf);
static void *api_pool(ngx_conf_t *cf);
static void *api_location(ngx_conf_t *cf);
static char *api_merge(ngx_conf_t *cf, void *parent, void *child);
static char *api_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static char *api_metrics_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static ngx_int_t api_metrics(ngx_http_request_t *r);
static ngx_int_t api_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t api_access(ngx_http_request_t *r);
static ngx_int_t api_header_filter(ngx_http_request_t *r);
static ngx_int_t api_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t api_log(ngx_http_request_t *r);
static ngx_int_t api_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);

#define API_LOC (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)
#define API_STRING(name, member) \
    { ngx_string(name), API_LOC|NGX_CONF_TAKE1, ngx_conf_set_str_slot, \
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(api_location_t, member), NULL }

static ngx_command_t api_commands[] = {
    { ngx_string("scdn_api"), API_LOC|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(api_location_t, enabled), NULL },
    { ngx_string("scdn_api_dispatch"), NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(api_location_t, dispatch), NULL },
    { ngx_string("scdn_api_inspect_body"), API_LOC|NGX_CONF_TAKE1, ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(api_location_t, inspect), NULL },
    { ngx_string("scdn_api_stream_timeout"), API_LOC|NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(api_location_t, stream_timeout), NULL },
    API_STRING("scdn_api_dynamic_location", dynamic_location),
    API_STRING("scdn_api_ai_location", ai_location),
    API_STRING("scdn_api_stream_location", stream_location),
    API_STRING("scdn_api_grpc_location", grpc_location),
    API_STRING("scdn_api_websocket_location", websocket_location),
    { ngx_string("scdn_api_zone"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      api_zone, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_api_metrics"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      api_metrics_directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    ngx_null_command
};

static ngx_http_module_t api_context = {
    api_preconfiguration, api_postconfiguration, api_main, NULL,
    api_pool, NULL, api_location, api_merge
};

ngx_module_t ngx_http_scdn_api_module = {
    NGX_MODULE_V1, &api_context, api_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

static ngx_str_t api_names[] = {
    ngx_string("web"), ngx_string("api"), ngx_string("ai"),
    ngx_string("stream"), ngx_string("grpc"), ngx_string("websocket")
};

static void *
api_main(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(api_main_t));
}

static void *
api_pool(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(api_pool_t));
}

static void *
api_location(ngx_conf_t *cf)
{
    api_location_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf != NULL) {
        conf->enabled = NGX_CONF_UNSET;
        conf->dispatch = NGX_CONF_UNSET;
        conf->inspect = NGX_CONF_UNSET_SIZE;
        conf->stream_timeout = NGX_CONF_UNSET_MSEC;
    }
    return conf;
}

static char *
api_merge(ngx_conf_t *cf, void *parent, void *child)
{
    api_location_t *prev = parent, *conf = child;
    ngx_str_t *locations[5];
    ngx_uint_t i;
    (void) cf;
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->dispatch, prev->dispatch, 0);
    ngx_conf_merge_size_value(conf->inspect, prev->inspect, 16384);
    ngx_conf_merge_msec_value(conf->stream_timeout, prev->stream_timeout, 600000);
    ngx_conf_merge_str_value(conf->dynamic_location, prev->dynamic_location, "");
    ngx_conf_merge_str_value(conf->ai_location, prev->ai_location, "");
    ngx_conf_merge_str_value(conf->stream_location, prev->stream_location, "");
    ngx_conf_merge_str_value(conf->grpc_location, prev->grpc_location, "");
    ngx_conf_merge_str_value(conf->websocket_location, prev->websocket_location, "");
    if (conf->inspect > 65536) { return "scdn_api_inspect_body must be at most 64k"; }
    if (conf->stream_timeout < 1000 || conf->stream_timeout > 3600000) {
        return "scdn_api_stream_timeout must be between 1s and 1h";
    }
    locations[0] = &conf->dynamic_location; locations[1] = &conf->ai_location;
    locations[2] = &conf->stream_location; locations[3] = &conf->grpc_location;
    locations[4] = &conf->websocket_location;
    for (i = 0; i < 5; i++) {
        if (locations[i]->len && locations[i]->data[0] != '@') {
            return "scdn_api profile locations must be named locations";
        }
    }
    return NGX_CONF_OK;
}

static void
api_cleanup(void *data)
{
    (void) data;
}

/* Internal redirects clear module ctx, while pool cleanup records survive. */
static api_request_t *
api_request(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t *cleanup;
    api_request_t *ctx = ngx_http_get_module_ctx(r, ngx_http_scdn_api_module);
    if (ctx != NULL && ctx->owner == r) { return ctx; }
    for (cleanup = r->pool->cleanup; cleanup != NULL; cleanup = cleanup->next) {
        if (cleanup->handler == api_cleanup
            && ((api_request_t *) cleanup->data)->owner == r) {
            ctx = cleanup->data;
            ngx_http_set_ctx(r, ctx, ngx_http_scdn_api_module);
            return ctx;
        }
    }
    cleanup = ngx_pool_cleanup_add(r->pool, sizeof(*ctx));
    if (cleanup == NULL) { return NULL; }
    cleanup->handler = api_cleanup;
    ctx = cleanup->data; ngx_memzero(ctx, sizeof(*ctx)); ctx->owner = r;
    ngx_str_set(&ctx->reason, "default");
    ngx_http_set_ctx(r, ctx, ngx_http_scdn_api_module);
    return ctx;
}

static ngx_table_elt_t *
api_find_header(ngx_http_request_t *r, const char *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *headers = part->elts;
    ngx_uint_t i;
    size_t length = ngx_strlen(name);
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) { break; }
            part = part->next; headers = part->elts; i = 0;
        }
        if (headers[i].hash && headers[i].key.len == length
            && ngx_strncasecmp(headers[i].key.data, (u_char *) name, length) == 0) {
            return &headers[i];
        }
    }
    return NULL;
}

static ngx_flag_t
api_contains(const ngx_str_t *value, const char *text)
{
    size_t i, length = ngx_strlen(text);
    if (value == NULL || value->len < length) { return 0; }
    for (i = 0; i <= value->len - length; i++) {
        if (ngx_strncasecmp(value->data + i, (u_char *) text, length) == 0) { return 1; }
    }
    return 0;
}

static ngx_flag_t
api_mime(const ngx_str_t *value, const char *mime)
{
    size_t length = ngx_strlen(mime);
    return value != NULL && value->len >= length
        && ngx_strncasecmp(value->data, (u_char *) mime, length) == 0
        && (value->len == length || value->data[length] == ';' || value->data[length] == ' ');
}

static ngx_flag_t
api_json_mime(const ngx_str_t *value)
{
    size_t end;
    if (api_mime(value, "application/json")) { return 1; }
    if (value == NULL || value->len < 17
        || ngx_strncasecmp(value->data, (u_char *) "application/", 12) != 0) { return 0; }
    for (end = 12; end < value->len && value->data[end] != ';' && value->data[end] != ' '; end++) { }
    return end >= 17 && ngx_strncasecmp(value->data + end - 5, (u_char *) "+json", 5) == 0;
}

static ngx_flag_t
api_suffix(const ngx_str_t *uri, const char *suffix)
{
    size_t length = ngx_strlen(suffix);
    return uri->len >= length
        && ngx_memcmp(uri->data + uri->len - length, suffix, length) == 0;
}

static ngx_flag_t
api_ai_path(ngx_str_t *uri)
{
    static const char *paths[] = {
        "/v1/chat/completions", "/v1/completions", "/v1/responses",
        "/v1/messages", "/v1/embeddings", "/v1/images/generations",
        "/v1/audio/transcriptions", "/v1/audio/speech", "/api/chat",
        "/api/generate", "/api/embed", "/api/embeddings",
        ":generateContent", ":streamGenerateContent", NULL
    };
    ngx_uint_t i;
    for (i = 0; paths[i] != NULL; i++) { if (api_suffix(uri, paths[i])) { return 1; } }
    return 0;
}

static void
api_set_kind(api_request_t *ctx, ngx_uint_t kind, const char *reason)
{
    ctx->kind = kind;
    ctx->reason.data = (u_char *) reason; ctx->reason.len = ngx_strlen(reason);
}

static void
api_classify_headers(ngx_http_request_t *r, api_request_t *ctx)
{
    ngx_table_elt_t *content = r->headers_in.content_type;
    ngx_table_elt_t *accept = api_find_header(r, "accept");
    ngx_table_elt_t *requested = api_find_header(r, "x-requested-with");
    ngx_table_elt_t *upgrade = api_find_header(r, "upgrade");
    ngx_table_elt_t *control = api_find_header(r, "cache-control");
    ngx_table_elt_t *pragma = api_find_header(r, "pragma");
    if (ctx->headers_done) { return; }
    ctx->headers_done = 1;
    ctx->private_request = api_find_header(r, "authorization") != NULL
        || api_find_header(r, "proxy-authorization") != NULL
        || api_find_header(r, "cookie") != NULL
        || api_find_header(r, "x-api-key") != NULL
        || api_find_header(r, "api-key") != NULL
        || (control && (api_contains(&control->value, "no-cache")
            || api_contains(&control->value, "no-store")))
        || (pragma && api_contains(&pragma->value, "no-cache"))
        || r->headers_in.content_length_n > 0 || r->headers_in.chunked;
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))
        || (content && api_json_mime(&content->value))
        || (accept && (api_contains(&accept->value, "application/json")
            || api_contains(&accept->value, "+json")))
        || (requested && api_contains(&requested->value, "XMLHttpRequest"))
        || (r->uri.len >= 5 && ngx_memcmp(r->uri.data, "/api/", 5) == 0)
        || (r->uri.len == 4 && ngx_memcmp(r->uri.data, "/api", 4) == 0)
        || (r->uri.len >= 4 && ngx_memcmp(r->uri.data, "/v1/", 4) == 0)
        || api_suffix(&r->uri, "/graphql")) {
        api_set_kind(ctx, API_DYNAMIC, "request_api");
    }
    if (accept && api_contains(&accept->value, "text/event-stream")) {
        api_set_kind(ctx, API_STREAM, "accept_sse"); ctx->stream = 1;
    }
    if (api_ai_path(&r->uri) || api_find_header(r, "anthropic-version") != NULL) {
        api_set_kind(ctx, API_AI, "ai_endpoint");
    }
    if (content && (api_mime(&content->value, "application/grpc")
        || api_contains(&content->value, "application/grpc+"))) {
        api_set_kind(ctx, API_GRPC, "grpc_content_type"); ctx->stream = 1;
    }
    if (upgrade && api_contains(&upgrade->value, "websocket")) {
        api_set_kind(ctx, API_WEBSOCKET, "websocket_upgrade"); ctx->stream = 1;
    }
}

static void
api_inspect_body(ngx_http_request_t *r, api_request_t *ctx, size_t maximum)
{
    ngx_chain_t *chain;
    ngx_buf_t *buffer;
    u_char *body, *out;
    size_t length = 0;
    scdn_api_json_t signals;
    if (r->request_body == NULL || r->request_body->temp_file != NULL) { return; }
    for (chain = r->request_body->bufs; chain; chain = chain->next) {
        buffer = chain->buf;
        if (buffer->in_file || !ngx_buf_in_memory(buffer) || buffer->last < buffer->pos) { return; }
        if ((size_t) (buffer->last - buffer->pos) > maximum - length) { return; }
        length += buffer->last - buffer->pos;
    }
    if (length == 0) { return; }
    body = ngx_pnalloc(r->pool, length);
    if (body == NULL) { return; }
    out = body;
    for (chain = r->request_body->bufs; chain; chain = chain->next) {
        out = ngx_cpymem(out, chain->buf->pos, chain->buf->last - chain->buf->pos);
    }
    if (scdn_api_json(body, length, &signals) && signals.model && signals.input) {
        api_set_kind(ctx, API_AI, "json_schema");
        if (signals.stream) { ctx->stream = 1; }
    }
}

static void
api_body_ready(ngx_http_request_t *r)
{
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    api_request_t *ctx = api_request(r);
    if (ctx == NULL) { ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); return; }
    api_inspect_body(r, ctx, conf->inspect);
    ctx->prepared = 1; r->preserve_body = 1;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

ngx_int_t
ngx_http_scdn_api_prepare(ngx_http_request_t *r)
{
    ngx_int_t rc;
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    api_request_t *ctx;
    ngx_table_elt_t *encoding;
    if (!conf->enabled) { return NGX_DECLINED; }
    ctx = api_request(r);
    if (ctx == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ctx->prepared) { return NGX_DECLINED; }
    api_classify_headers(r, ctx);
    encoding = api_find_header(r, "content-encoding");
    if (r != r->main || ctx->kind == API_AI || ctx->kind == API_GRPC
        || ctx->kind == API_WEBSOCKET || conf->inspect == 0
        || r->headers_in.content_type == NULL
        || !api_json_mime(&r->headers_in.content_type->value)
        || r->headers_in.content_length_n <= 0 || r->headers_in.chunked
        || (uint64_t) r->headers_in.content_length_n > conf->inspect
        || (encoding && !api_mime(&encoding->value, "identity"))) {
        ctx->prepared = 1; return NGX_DECLINED;
    }
    if (ctx->body_started) { return NGX_DONE; }
    ctx->body_started = 1;
    r->request_body_in_single_buf = 1;
    rc = ngx_http_read_client_request_body(r, api_body_ready);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { return rc; }
    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}

ngx_str_t *
ngx_http_scdn_api_location(ngx_http_request_t *r, ngx_str_t *fallback)
{
    ngx_str_t *selected = NULL;
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    api_request_t *ctx;
    if (!conf->enabled) { return fallback; }
    ctx = api_request(r);
    if (ctx == NULL) { return fallback; }
    switch (ctx->kind) {
    case API_DYNAMIC: selected = &conf->dynamic_location; break;
    case API_AI: selected = &conf->ai_location; break;
    case API_STREAM: selected = &conf->stream_location; break;
    case API_GRPC: selected = &conf->grpc_location; break;
    case API_WEBSOCKET: selected = &conf->websocket_location; break;
    default: break;
    }
    return selected != NULL && selected->len != 0 ? selected : fallback;
}

static ngx_int_t
api_access(ngx_http_request_t *r)
{
    ngx_int_t rc = ngx_http_scdn_api_prepare(r);
    ngx_str_t empty = ngx_null_string, *location;
    api_location_t *conf;
    api_request_t *ctx;
    if (rc != NGX_DECLINED) { return rc; }
    conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    if (!conf->enabled || !conf->dispatch) { return NGX_DECLINED; }
    ctx = api_request(r);
    if (ctx == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ctx->dispatched) { return NGX_DECLINED; }
    location = ngx_http_scdn_api_location(r, &empty);
    if (location->len == 0) { return NGX_DECLINED; }
    ctx->dispatched = 1;
    (void) ngx_http_named_location(r, location);
    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}

static void
api_response(ngx_http_request_t *r, api_request_t *ctx)
{
    ngx_str_t *type = &r->headers_out.content_type;
    if (api_mime(type, "text/event-stream") || api_mime(type, "application/x-ndjson")
        || api_mime(type, "application/json-seq")) {
        ctx->stream = 1;
        if (ctx->kind != API_AI && ctx->kind != API_GRPC && ctx->kind != API_WEBSOCKET) {
            api_set_kind(ctx, API_STREAM, "response_stream");
        }
    } else if (ctx->kind == API_WEB && api_json_mime(type)) {
        api_set_kind(ctx, API_DYNAMIC, "response_json");
    }
}

static ngx_int_t
api_header_filter(ngx_http_request_t *r)
{
    api_request_t *ctx;
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    ngx_http_upstream_t *upstream = r->upstream;
    if (!conf->enabled) { return api_next_header(r); }
    ctx = api_request(r);
    if (ctx == NULL) { return NGX_ERROR; }
    api_classify_headers(r, ctx);
    api_response(r, ctx);
    if (ctx->kind != API_WEB || ctx->private_request) {
#if (NGX_HTTP_CACHE)
        if (upstream != NULL) { upstream->cacheable = 0; }
#endif
    }
    if (ctx->stream || ctx->kind == API_AI) {
        /* Never mutate a shared location/upstream configuration. */
#if (NGX_HTTP_GZIP)
        r->gzip_tested = 1; r->gzip_ok = 0;
#endif
        if (upstream != NULL && !upstream->upgrade) {
            upstream->buffering = 0;
            if (ctx->upstream_conf == NULL) {
                ctx->upstream_conf = ngx_palloc(r->pool, sizeof(*upstream->conf));
                if (ctx->upstream_conf == NULL) { return NGX_ERROR; }
                *ctx->upstream_conf = *upstream->conf;
            }
            upstream->conf = ctx->upstream_conf;
            upstream->conf->ignore_client_abort = 0;
            upstream->conf->read_timeout = conf->stream_timeout;
        }
    }
    return api_next_header(r);
}

static ngx_int_t
api_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *chain;
    api_request_t *ctx = ngx_http_get_module_ctx(r, ngx_http_scdn_api_module);
    if (ctx != NULL && (ctx->stream || ctx->kind == API_AI)) {
        for (chain = in; chain; chain = chain->next) {
            if (ngx_buf_size(chain->buf) > 0) { chain->buf->flush = 1; }
        }
    }
    return api_next_body(r, in);
}

static ngx_int_t
api_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t value = ngx_null_string;
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    api_request_t *ctx;
    if (!conf->enabled) { v->not_found = 1; return NGX_OK; }
    ctx = api_request(r);
    if (ctx == NULL) { return NGX_ERROR; }
    api_classify_headers(r, ctx);
    if (data == 0) { value = api_names[ctx->kind]; }
    else if (data == 1) { value = ctx->reason; }
    else if (data == 2) {
        /* proxy_no_cache runs after header filters on a buffered response. */
        api_response(r, ctx);
        if (ctx->kind != API_WEB || ctx->private_request) { ngx_str_set(&value, "1"); }
        else { ngx_str_set(&value, "0"); }
    } else if (data == 3) {
        if (ctx->stream) { ngx_str_set(&value, "1"); } else { ngx_str_set(&value, "0"); }
    } else if (data == 4) {
        if (ctx->kind == API_WEBSOCKET) { ngx_str_set(&value, "upgrade"); }
    } else { ngx_str_set(&value, "api-policy-v1"); }
    v->data = value.data; v->len = value.len; v->valid = 1;
    v->no_cacheable = 1; v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
api_preconfiguration(ngx_conf_t *cf)
{
    static ngx_str_t names[] = {
        ngx_string("scdn_api_kind"), ngx_string("scdn_api_reason"),
        ngx_string("scdn_api_skip_cache"), ngx_string("scdn_api_stream"),
        ngx_string("scdn_api_connection"), ngx_string("scdn_api_cache_namespace")
    };
    ngx_http_variable_t *variable;
    ngx_uint_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        variable = ngx_http_add_variable(cf, &names[i], NGX_HTTP_VAR_NOCACHEABLE);
        if (variable == NULL) { return NGX_ERROR; }
        variable->get_handler = api_variable; variable->data = i;
    }
    return NGX_OK;
}

static ngx_int_t
api_init_zone(ngx_shm_zone_t *zone, void *old)
{
    api_main_t *main = zone->data, *previous = old;
    ngx_slab_pool_t *slab = (ngx_slab_pool_t *) zone->shm.addr;
    if (previous != NULL) { main->shared = previous->shared; }
    else if (zone->shm.exists) { main->shared = slab->data; }
    else { main->shared = ngx_slab_calloc(slab, sizeof(api_shared_t)); slab->data = main->shared; }
    return main->shared != NULL ? NGX_OK : NGX_ERROR;
}

static char *
api_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    api_main_t *main = data;
    ngx_str_t *values = cf->args->elts;
    ssize_t size = ngx_parse_size(&values[2]);
    (void) cmd;
    if (main->zone != NULL) { return "is duplicate"; }
    if (size < (ssize_t) (8 * ngx_pagesize) || size > 1024 * 1024) {
        return "scdn_api_zone requires 8 pages to 1m";
    }
    main->zone = ngx_shared_memory_add(cf, &values[1], size, &ngx_http_scdn_api_module);
    if (main->zone == NULL) { return NGX_CONF_ERROR; }
    main->zone->data = main; main->zone->init = api_init_zone;
    return NGX_CONF_OK;
}

static ngx_int_t
api_log(ngx_http_request_t *r)
{
    api_main_t *main;
    api_request_t *ctx;
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    if (r != r->main || !conf->enabled) { return NGX_OK; }
    main = ngx_http_get_module_main_conf(r, ngx_http_scdn_api_module);
    if (main->shared == NULL) { return NGX_OK; }
    ctx = api_request(r);
    if (ctx == NULL || ctx->recorded) { return NGX_OK; }
    ctx->recorded = 1;
    (void) ngx_atomic_fetch_add(&main->shared->kinds[ctx->kind], 1);
    if (ctx->stream) { (void) ngx_atomic_fetch_add(&main->shared->streaming, 1); }
    return NGX_OK;
}

/* A shared nginx keepalive pool normally keys by peer address. A dynamic
 * proxy_ssl_name may differ between requests to that address. Check the
 * established TLS identity and SSL context before accepting a cached peer. */
static ngx_int_t
api_get_peer(ngx_peer_connection_t *pc, void *data)
{
    api_peer_t *peer = data;
    ngx_http_upstream_t *u = peer->request->upstream;
    ngx_int_t rc = peer->get(pc, peer->data);
    ngx_connection_t *connection;
    ngx_flag_t compatible;
#if (NGX_HTTP_SSL)
    ngx_str_t name;
    const char *actual;
    u_char *colon;
#endif
    if (rc != NGX_DONE || pc->connection == NULL) { return rc; }
    connection = pc->connection;
    compatible = 1;
#if (NGX_HTTP_SSL)
    if ((u->ssl != 0) != (connection->ssl != NULL)) { compatible = 0; }
    if (compatible && u->ssl) {
        name = u->ssl_name;
        if (u->conf->ssl_name != NULL
            && ngx_http_complex_value(peer->request, u->conf->ssl_name, &name) != NGX_OK) {
            return NGX_ERROR;
        }
        colon = name.len && name.data[0] != '['
            ? ngx_strlchr(name.data, name.data + name.len, ':') : NULL;
        if (colon != NULL) { name.len = colon - name.data; }
        actual = SSL_get_servername(connection->ssl->connection, TLSEXT_NAMETYPE_host_name);
        if (SSL_get_SSL_CTX(connection->ssl->connection) != u->conf->ssl->ctx
            || (u->conf->ssl_certificate != NULL && u->conf->ssl_certificate->lengths != NULL)
            || (u->conf->ssl_certificate_key != NULL && u->conf->ssl_certificate_key->lengths != NULL)) {
            compatible = 0;
        }
        if (u->conf->ssl_server_name && actual != NULL
            && (ngx_strlen(actual) != name.len
                || ngx_strncasecmp((u_char *) actual, name.data, name.len) != 0)) {
            compatible = 0;
        }
        if (u->conf->ssl_server_name && actual == NULL && name.len
            && name.data[0] != '[' && ngx_inet_addr(name.data, name.len) == INADDR_NONE) {
            compatible = 0;
        }
        if (u->conf->ssl_verify
            && (SSL_get_verify_result(connection->ssl->connection) != X509_V_OK
                || ngx_ssl_check_host(connection, &name) != NGX_OK)) {
            compatible = 0;
        }
    }
#else
    (void) u;
#endif
    if (compatible) { return rc; }
    /* The keepalive module already returned its cache slot to the free queue.
     * The selected round-robin peer remains acquired for this new connect. */
#if (NGX_HTTP_SSL)
    if (connection->ssl != NULL) {
        connection->ssl->no_wait_shutdown = 1;
        connection->ssl->no_send_shutdown = 1;
        (void) ngx_ssl_shutdown(connection);
    }
#endif
    ngx_destroy_pool(connection->pool);
    ngx_close_connection(connection);
    pc->connection = NULL; pc->cached = 0;
    return NGX_OK;
}

static void
api_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    api_peer_t *peer = data;
    peer->free(pc, peer->data, state);
}

static void
api_notify_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t type)
{
    api_peer_t *peer = data;
    if (peer->notify != NULL) { peer->notify(pc, peer->data, type); }
}

#if (NGX_HTTP_SSL)
static ngx_flag_t
api_dynamic_tls(api_peer_t *peer)
{
    ngx_http_upstream_conf_t *conf = peer->request->upstream->conf;
    return (conf->ssl_name != NULL && conf->ssl_name->lengths != NULL)
        || (conf->ssl_certificate != NULL && conf->ssl_certificate->lengths != NULL)
        || (conf->ssl_certificate_key != NULL && conf->ssl_certificate_key->lengths != NULL);
}

static ngx_int_t
api_set_session(ngx_peer_connection_t *pc, void *data)
{
    api_peer_t *peer = data;
    /* Stock peer session caches do not have a dynamic SNI/certificate key.
     * Keep established connections reusable, but do a full handshake on a
     * new connection when the configured TLS identity is variable. */
    if (api_dynamic_tls(peer) || peer->set_session == NULL) { return NGX_OK; }
    return peer->set_session(pc, peer->data);
}

static void
api_save_session(ngx_peer_connection_t *pc, void *data)
{
    api_peer_t *peer = data;
    if (!api_dynamic_tls(peer) && peer->save_session != NULL) { peer->save_session(pc, peer->data); }
}
#endif

static ngx_int_t
api_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    api_pool_t *pool = us->srv_conf[ngx_http_scdn_api_module.ctx_index];
    api_location_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_api_module);
    api_peer_t *peer;
    ngx_int_t rc = pool->original_init(r, us);
    if (rc != NGX_OK || !conf->enabled) { return rc; }
    peer = ngx_pcalloc(r->pool, sizeof(*peer));
    if (peer == NULL) { return NGX_ERROR; }
    peer->request = r; peer->data = r->upstream->peer.data;
    peer->get = r->upstream->peer.get; peer->free = r->upstream->peer.free;
    peer->notify = r->upstream->peer.notify;
    r->upstream->peer.data = peer;
    r->upstream->peer.get = api_get_peer; r->upstream->peer.free = api_free_peer;
    r->upstream->peer.notify = api_notify_peer;
#if (NGX_HTTP_SSL)
    peer->set_session = r->upstream->peer.set_session;
    peer->save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = api_set_session;
    r->upstream->peer.save_session = api_save_session;
#endif
    return NGX_OK;
}

static ngx_flag_t
api_local(ngx_http_request_t *r)
{
    struct sockaddr_storage peer;
    socklen_t length = sizeof(peer);
    struct sockaddr *address = (struct sockaddr *) &peer;
    /* realip may replace connection->sockaddr; authorize the actual socket. */
    if (getpeername(r->connection->fd, address, &length) != 0) { return 0; }
    if (address->sa_family == AF_UNIX) { return 1; }
    if (address->sa_family == AF_INET) {
        return (ntohl(((struct sockaddr_in *) address)->sin_addr.s_addr) >> 24) == 127;
    }
#if (NGX_HAVE_INET6)
    if (address->sa_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *) address)->sin6_addr);
    }
#endif
    return 0;
}

static ngx_int_t
api_metrics(ngx_http_request_t *r)
{
    api_main_t *main = ngx_http_get_module_main_conf(r, ngx_http_scdn_api_module);
    ngx_buf_t *buffer;
    ngx_chain_t chain;
    ngx_uint_t i;
    ngx_int_t rc;
    if (!api_local(r)) { return NGX_HTTP_FORBIDDEN; }
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) { return NGX_HTTP_NOT_ALLOWED; }
    if (r->args.len || r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->keepalive = 0; return NGX_HTTP_BAD_REQUEST;
    }
    if (main->shared == NULL) { return NGX_HTTP_SERVICE_UNAVAILABLE; }
    buffer = ngx_create_temp_buf(r->pool, 2048);
    if (buffer == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
        "# TYPE scdn_api_requests_total counter\n# TYPE scdn_api_stream_requests_total counter\n");
    for (i = 0; i < API_KINDS; i++) {
        buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
            "scdn_api_requests_total{kind=\"%V\"} %uA\n", &api_names[i], main->shared->kinds[i]);
    }
    buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
        "scdn_api_stream_requests_total %uA\n", main->shared->streaming);
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "text/plain; version=0.0.4");
    r->headers_out.content_length_n = buffer->last - buffer->pos;
    buffer->last_buf = r == r->main; buffer->last_in_chain = 1;
    chain.buf = buffer; chain.next = NULL;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }
    return ngx_http_output_filter(r, &chain);
}

static char *
api_metrics_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    ngx_http_core_loc_conf_t *core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    (void) cmd; (void) data;
    if (core->handler != NULL) { return "scdn_api_metrics conflicts with a content handler"; }
    core->handler = api_metrics;
    return NGX_CONF_OK;
}

static ngx_int_t
api_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *core = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_upstream_main_conf_t *upstreams = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    ngx_http_upstream_srv_conf_t **servers = upstreams->upstreams.elts;
    api_pool_t *pool;
    ngx_uint_t i;
    ngx_http_handler_pt *handler;
    for (i = 0; i < upstreams->upstreams.nelts; i++) {
        if (servers[i]->srv_conf == NULL || servers[i]->peer.init == NULL) { continue; }
        pool = servers[i]->srv_conf[ngx_http_scdn_api_module.ctx_index];
        if (pool == NULL) { continue; }
        pool->original_init = servers[i]->peer.init;
        servers[i]->peer.init = api_init_peer;
    }
    handler = ngx_array_push(&core->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (handler == NULL) { return NGX_ERROR; } *handler = api_access;
    handler = ngx_array_push(&core->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (handler == NULL) { return NGX_ERROR; } *handler = api_log;
    api_next_header = ngx_http_top_header_filter; ngx_http_top_header_filter = api_header_filter;
    api_next_body = ngx_http_top_body_filter; ngx_http_top_body_filter = api_body_filter;
    return NGX_OK;
}
