#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ngx_md5.h>

#if !(NGX_HTTP_CACHE)
#error "native-tier requires HTTP proxy cache support"
#endif
#define TIER_SLOTS 4096
#define TIER_FIELDS 6
#define TIER_KEY_MAX 8192
enum { TIER_FRONT = 1, TIER_BACK = 2 };
typedef struct { u_char digest[16]; ngx_msec_t since; ngx_uint_t hits; } tier_hot;
typedef struct {
    ngx_uint_t format;
    u_char token[64];
    ngx_atomic_t l1_hits, l2_hits, origin_reads, bypasses;
    tier_hot hot[TIER_SLOTS];
} tier_shared;
typedef struct {
    ngx_str_t socket, upstream;
    ngx_shm_zone_t *zone;
    ngx_slab_pool_t *slab;
    tier_shared *shared;
    ngx_uint_t hits;
    ngx_msec_t window;
} tier_main;
typedef struct {
    ngx_uint_t mode;
    ngx_http_complex_value_t selector, origin, fields[TIER_FIELDS - 1], bypass;
    ngx_flag_t identity, has_bypass, status;
    off_t l1_limit, l2_limit;
} tier_location;
typedef struct {
    ngx_http_request_t *owner;
    ngx_uint_t mode;
    ngx_flag_t skip, hot, recorded;
    ngx_str_t selector, origin, fields[TIER_FIELDS - 1], wire[TIER_FIELDS];
    ngx_http_upstream_t *upstream;
    ngx_int_t (*process_header)(ngx_http_request_t *r);
    time_t stored_expiry;
} tier_request;
static ngx_http_output_header_filter_pt tier_next_header;
extern ngx_module_t ngx_http_scdn_tier_module;
static void *create_main(ngx_conf_t *cf);
static void *create_location(ngx_conf_t *cf);
static char *merge_location(ngx_conf_t *cf, void *parent, void *child);
static char *directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t variables(ngx_conf_t *cf);
static ngx_int_t configure(ngx_conf_t *cf);
static ngx_int_t variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t access_handler(ngx_http_request_t *r);
static ngx_int_t header_filter(ngx_http_request_t *r);
static ngx_int_t status_handler(ngx_http_request_t *r);
static ngx_int_t zone_init(ngx_shm_zone_t *zone, void *previous);
static ngx_int_t tier_process_header(ngx_http_request_t *r);

static ngx_command_t commands[] = {
    { ngx_string("scdn_tier_zone"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2, directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_socket"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1, directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_heat"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2, directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_front"), NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_identity"), NGX_HTTP_LOC_CONF|NGX_CONF_TAKE5, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_bypass"), NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_max_size"), NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_backend"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_tier_status"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    ngx_null_command
};
static ngx_http_module_t context = {
    variables, configure, create_main, NULL, NULL, NULL, create_location, merge_location
};
ngx_module_t ngx_http_scdn_tier_module = {
    NGX_MODULE_V1, &context, commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

static int same(ngx_str_t value, const char *text)
{ return value.len == strlen(text) && !memcmp(value.data, text, value.len); }
static void *create_main(ngx_conf_t *cf)
{
    tier_main *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf) { conf->hits = 3; conf->window = 5400000; }
    return conf;
}
static void *create_location(ngx_conf_t *cf)
{
    tier_location *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf) { conf->l1_limit = NGX_CONF_UNSET; conf->l2_limit = NGX_CONF_UNSET; }
    return conf;
}
static char *merge_location(ngx_conf_t *cf, void *parent, void *child)
{
    tier_location *conf = child;
    tier_main *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_tier_module);
    (void) parent;
    if (conf->mode && (!main->zone || !main->socket.len)) return "requires scdn_tier_zone and scdn_tier_socket";
    if (conf->mode == TIER_FRONT && !conf->identity) return "front requires scdn_tier_identity";
    if (conf->mode == TIER_BACK && (conf->identity || conf->has_bypass)) return "backend derives identity and bypass from authenticated transport";
    if (conf->l1_limit == NGX_CONF_UNSET) conf->l1_limit = 512 * 1024 * 1024;
    if (conf->l2_limit == NGX_CONF_UNSET) conf->l2_limit = (off_t) 32 * 1024 * 1024 * 1024;
    if (conf->l1_limit > conf->l2_limit) return "L1 size limit must not exceed L2";
    return NGX_CONF_OK;
}
static ngx_int_t complex(ngx_conf_t *cf, ngx_str_t *value, ngx_http_complex_value_t *out)
{
    ngx_http_compile_complex_value_t compiled;
    ngx_memzero(&compiled, sizeof(compiled)); compiled.cf = cf; compiled.value = value; compiled.complex_value = out;
    return ngx_http_compile_complex_value(&compiled);
}
static char *directive(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_str_t *v = cf->args->elts;
    tier_main *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_tier_module);
    tier_location *conf = configuration;
    ngx_uint_t i;
    ssize_t size;
    if (same(cmd->name, "scdn_tier_zone")) {
        size = ngx_parse_size(&v[2]);
        if (main->zone || size < (ssize_t) (sizeof(tier_shared) + 16 * ngx_pagesize) || size > 16 * 1024 * 1024)
            return "requires a unique shared zone between 1m and 16m";
        main->zone = ngx_shared_memory_add(cf, &v[1], size, &ngx_http_scdn_tier_module);
        if (!main->zone) return NGX_CONF_ERROR;
        main->zone->data = main; main->zone->init = zone_init; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_socket")) {
        if (main->socket.len || v[1].len < 2 || v[1].len > 100 || v[1].data[0] != '/') return "requires one absolute Unix socket path";
        for (i = 0; i < v[1].len; i++) if (v[1].data[i] <= 32 || v[1].data[i] == ':' || v[1].data[i] == '$') return "invalid socket path";
        main->socket = v[1]; main->upstream.len = 12 + v[1].len + 1;
        main->upstream.data = ngx_pnalloc(cf->pool, main->upstream.len + 1);
        if (!main->upstream.data) return NGX_CONF_ERROR;
        main->upstream.len = ngx_sprintf(main->upstream.data, "http://unix:%V:", &v[1]) - main->upstream.data;
        return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_heat")) {
        ngx_int_t hits = ngx_atoi(v[1].data, v[1].len);
        ngx_int_t window = ngx_parse_time(&v[2], 0);
        if (hits < 1 || hits > 1000000 || window < 100 || window > 86400000) return "requires 1..1000000 hits and 100ms..24h window";
        main->hits = (ngx_uint_t) hits; main->window = (ngx_msec_t) window; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_front")) {
        if (conf->mode || complex(cf, &v[1], &conf->selector) != NGX_OK || complex(cf, &v[2], &conf->origin) != NGX_OK) return NGX_CONF_ERROR;
        conf->mode = TIER_FRONT; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_backend")) {
        if (conf->mode) return "duplicates tier mode";
        conf->mode = TIER_BACK; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_identity")) {
        if (conf->identity) return "duplicates identity";
        for (i = 0; i < 5; i++) if (complex(cf, &v[i + 1], &conf->fields[i]) != NGX_OK) return NGX_CONF_ERROR;
        conf->identity = 1; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_bypass")) {
        if (conf->has_bypass || complex(cf, &v[1], &conf->bypass) != NGX_OK) return NGX_CONF_ERROR;
        conf->has_bypass = 1; return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_max_size")) {
        if (conf->l1_limit != NGX_CONF_UNSET) return "duplicates object limits";
        conf->l1_limit = ngx_parse_offset(&v[1]); conf->l2_limit = ngx_parse_offset(&v[2]);
        if (conf->l1_limit <= 0 || conf->l2_limit <= 0) return "requires positive byte size limits";
        return NGX_CONF_OK;
    }
    if (same(cmd->name, "scdn_tier_status")) {
        ngx_http_core_loc_conf_t *location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (conf->status || location->handler) return "conflicts with content handler";
        conf->status = 1; location->handler = status_handler; return NGX_CONF_OK;
    }
    return NGX_CONF_ERROR;
}
static ngx_int_t zone_init(ngx_shm_zone_t *zone, void *previous)
{
    tier_main *main = zone->data, *old = previous;
    u_char random[32]; ngx_uint_t i;
    main->slab = (ngx_slab_pool_t *) zone->shm.addr;
    if (old) main->shared = old->shared;
    else if (zone->shm.exists) main->shared = main->slab->data;
    else {
        main->shared = ngx_slab_calloc(main->slab, sizeof(tier_shared));
        if (!main->shared || RAND_bytes(random, 32) != 1) return NGX_ERROR;
        main->shared->format = 1;
        for (i = 0; i < 32; i++) {
            main->shared->token[i * 2] = "0123456789abcdef"[random[i] >> 4];
            main->shared->token[i * 2 + 1] = "0123456789abcdef"[random[i] & 15];
        }
        OPENSSL_cleanse(random, sizeof(random)); main->slab->data = main->shared;
    }
    return main->shared && main->shared->format == 1 ? NGX_OK : NGX_ERROR;
}
static ngx_str_t *find_header(ngx_list_t *list, const char *name)
{
    ngx_list_part_t *part = &list->part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i; ngx_str_t *value = NULL;
    for (i = 0; ; i++) {
        if (i >= part->nelts) { if (!part->next) break; part = part->next; h = part->elts; i = 0; }
        if (h[i].hash && h[i].key.len == strlen(name) && !ngx_strncasecmp(h[i].key.data, (u_char *) name, h[i].key.len)) {
            if (value) return NULL;
            value = &h[i].value;
        }
    }
    return value;
}
static ngx_flag_t local_socket(ngx_http_request_t *r)
{
    struct sockaddr_storage peer; socklen_t size = sizeof(peer);
    return getpeername(r->connection->fd, (struct sockaddr *) &peer, &size) == 0 && peer.ss_family == AF_UNIX;
}
static ngx_flag_t private_request(ngx_http_request_t *r)
{
    ngx_str_t *value;
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) || r->headers_in.content_length_n > 0 || r->headers_in.chunked
        || r->headers_in.authorization || find_header(&r->headers_in.headers, "Cookie")
        || find_header(&r->headers_in.headers, "X-API-Key") || find_header(&r->headers_in.headers, "Upgrade")) return 1;
    value = find_header(&r->headers_in.headers, "Cache-Control");
    if (value && (ngx_strlcasestrn(value->data, value->data + value->len, (u_char *) "no-cache", 7)
                 || ngx_strlcasestrn(value->data, value->data + value->len, (u_char *) "no-store", 7))) return 1;
    return 0;
}
static ngx_flag_t hot(tier_main *main, tier_request *ctx)
{
    ngx_md5_t md5; u_char digest[16]; ngx_uint_t index;
    tier_hot *entry;
    ngx_md5_init(&md5); ngx_md5_update(&md5, ctx->fields[2].data, ctx->fields[2].len);
    ngx_md5_update(&md5, (u_char *) "\0", 1); ngx_md5_update(&md5, ctx->fields[3].data, ctx->fields[3].len);
    ngx_md5_final(digest, &md5);
    index = ngx_crc32_short(digest, 16) % TIER_SLOTS;
    ngx_shmtx_lock(&main->slab->mutex); entry = &main->shared->hot[index];
    if (memcmp(entry->digest, digest, 16) || (ngx_msec_int_t) (ngx_current_msec - entry->since) >= (ngx_msec_int_t) main->window) {
        memcpy(entry->digest, digest, 16); entry->since = ngx_current_msec; entry->hits = 0;
    }
    if (entry->hits < 1000000) entry->hits++;
    index = entry->hits >= main->hits; ngx_shmtx_unlock(&main->slab->mutex); return index;
}
static int safe_value(ngx_str_t value, size_t maximum)
{
    size_t i;
    if (!value.len || value.len > maximum) return 0;
    for (i = 0; i < value.len; i++) if (value.data[i] < 32 || value.data[i] == 127) return 0;
    return 1;
}
static tier_request *request_context(ngx_http_request_t *r)
{
    static const char *names[TIER_FIELDS] = { "X-Tier-Origin", "X-Tier-Host", "X-Tier-SNI", "X-Tier-Scope", "X-Tier-Key", "X-Tier-Resource" };
    tier_request *ctx = ngx_http_get_module_ctx(r, ngx_http_scdn_tier_module);
    tier_location *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_tier_module);
    tier_main *main = ngx_http_get_module_main_conf(r, ngx_http_scdn_tier_module);
    ngx_uint_t i;
    ngx_str_t *value, bypass, *field;
    if (ctx && ctx->owner == r) return ctx;
    if (!conf->mode || !main->shared) return NULL;
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx)); if (!ctx) return NULL;
    ctx->owner = r; ctx->mode = conf->mode;
    if (conf->mode == TIER_FRONT) {
        if (ngx_http_complex_value(r, &conf->selector, &ctx->selector) != NGX_OK
            || ngx_http_complex_value(r, &conf->origin, &ctx->origin) != NGX_OK) return NULL;
        for (i = 0; i < 5; i++) if (ngx_http_complex_value(r, &conf->fields[i], &ctx->fields[i]) != NGX_OK) return NULL;
        if (!same(ctx->selector, "off") && !same(ctx->selector, "l1") && !same(ctx->selector, "l2") && !same(ctx->selector, "auto")) return NULL;
        ctx->skip = same(ctx->selector, "off") || private_request(r);
        if (conf->has_bypass) {
            if (ngx_http_complex_value(r, &conf->bypass, &bypass) != NGX_OK) return NULL;
            if (bypass.len && !same(bypass, "0")) ctx->skip = 1;
        }
        if (!ctx->skip) ctx->hot = same(ctx->selector, "l1") || (same(ctx->selector, "auto") && hot(main, ctx));
        for (i = 0; i < TIER_FIELDS; i++) {
            field = i ? &ctx->fields[i - 1] : &ctx->origin;
            if (!safe_value(*field, i == 4 ? TIER_KEY_MAX : 4096)) return NULL;
            ctx->wire[i].data = ngx_pnalloc(r->pool, ngx_base64_encoded_length(field->len));
            if (!ctx->wire[i].data) return NULL;
            ngx_encode_base64url(&ctx->wire[i], field);
        }
    } else {
        value = find_header(&r->headers_in.headers, "X-Tier-Token");
        if (!local_socket(r) || !value || value->len != 64 || CRYPTO_memcmp(value->data, main->shared->token, 64)) return NULL;
        for (i = 0; i < TIER_FIELDS; i++) {
            value = find_header(&r->headers_in.headers, names[i]);
            if (!value || value->len > ngx_base64_encoded_length(TIER_KEY_MAX)) return NULL;
            field = i ? &ctx->fields[i - 1] : &ctx->origin;
            field->data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(value->len));
            if (!field->data || ngx_decode_base64url(field, value) != NGX_OK || !safe_value(*field, i == 4 ? TIER_KEY_MAX : 4096)) return NULL;
        }
        ngx_str_set(&ctx->selector, "l2"); ctx->skip = private_request(r);
    }
    if (ctx->origin.len < 8 || (memcmp(ctx->origin.data, "http://", 7) && memcmp(ctx->origin.data, "https://", 8))) return NULL;
    ngx_http_set_ctx(r, ctx, ngx_http_scdn_tier_module); return ctx;
}
static ngx_int_t access_handler(ngx_http_request_t *r)
{
    tier_location *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_tier_module);
    if (conf->mode && !request_context(r)) return NGX_HTTP_FORBIDDEN;
    return NGX_DECLINED;
}
static ngx_int_t tier_process_header(ngx_http_request_t *r)
{
    tier_request *ctx = ngx_http_get_module_ctx(r, ngx_http_scdn_tier_module);
    if (!ctx || !ctx->process_header) return NGX_ERROR;
    /* Parsing cached Cache-Control recalculates c->valid_sec from now. Capture
     * the validated file-cache deadline before core parses cached HTTP headers. */
    if (r->cached && r->cache) ctx->stored_expiry = r->cache->valid_sec;
    return ctx->process_header(r);
}
static ngx_int_t variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    tier_request *ctx = request_context(r);
    tier_main *main = ngx_http_get_module_main_conf(r, ngx_http_scdn_tier_module);
    tier_location *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_tier_module);
    ngx_str_t value = ngx_null_string, *fresh;
    ngx_flag_t no_store;
    if (!ctx) { v->not_found = 1; return NGX_OK; }
    if (r->upstream && r->upstream->process_header && ctx->upstream != r->upstream) {
        ctx->upstream = r->upstream; ctx->process_header = r->upstream->process_header;
        r->upstream->process_header = tier_process_header;
    }
    if (data == 0) {
        if (ctx->mode == TIER_FRONT && !ctx->skip) value = main->upstream; else value = ctx->origin;
    } else if (data == 1) {
        if (ctx->skip || (ctx->mode == TIER_FRONT && !ctx->hot)) { ngx_str_set(&value, "off"); }
        else if (ctx->mode == TIER_FRONT) { ngx_str_set(&value, "l1"); } else { ngx_str_set(&value, "l2"); }
    } else if (data >= 2 && data <= 6) value = ctx->fields[data - 2];
    else if (data == 7) value = ctx->origin;
    else if (data == 8) {
        if (ctx->mode == TIER_FRONT && !ctx->skip) { value.data = main->shared->token; value.len = 64; }
    } else if (data >= 9 && data <= 14) {
        if (ctx->mode == TIER_FRONT && !ctx->skip) value = ctx->wire[data - 9];
    } else if (data == 15) {
        no_store = ctx->skip;
        if (r->upstream && (r->upstream->headers_in.content_length_n < 0
            || r->upstream->headers_in.content_length_n > (ctx->mode == TIER_FRONT ? conf->l1_limit : conf->l2_limit))) no_store = 1;
        if (ctx->mode == TIER_FRONT && !ctx->skip && r->upstream) {
            fresh = find_header(&r->upstream->headers_in.headers, "X-Tier-Store");
            if (!fresh || !same(*fresh, "1")) no_store = 1;
        }
        if (no_store) { ngx_str_set(&value, "1"); } else { ngx_str_set(&value, "0"); }
    } else if (data == 16) {
        if (ctx->mode == TIER_FRONT) {
            if (r->upstream && r->upstream->cache_status == NGX_HTTP_CACHE_EXPIRED) { ngx_str_set(&value, "1"); }
        } else {
            fresh = find_header(&r->headers_in.headers, "X-Tier-Validate");
            if (fresh && same(*fresh, "1")) { ngx_str_set(&value, "1"); }
        }
    }
    /* Core script copies a valid value even at length zero. An absent wire
     * field must therefore carry a valid empty buffer, not a NULL pointer. */
    if (!value.data) { ngx_str_set(&value, ""); }
    v->data = value.data; v->len = value.len; v->valid = 1; v->not_found = 0; v->no_cacheable = 1;
    return NGX_OK;
}
static ngx_int_t variables(ngx_conf_t *cf)
{
    static const char *names[] = { "scdn_tier_upstream", "scdn_tier_cache", "scdn_tier_host", "scdn_tier_sni", "scdn_tier_scope", "scdn_tier_key", "scdn_tier_resource", "scdn_tier_origin", "scdn_tier_token", "scdn_tier_wire_origin", "scdn_tier_wire_host", "scdn_tier_wire_sni", "scdn_tier_wire_scope", "scdn_tier_wire_key", "scdn_tier_wire_resource", "scdn_tier_no_store", "scdn_tier_validate" };
    ngx_http_variable_t *v; ngx_str_t name; ngx_uint_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        name.data = (u_char *) names[i]; name.len = strlen(names[i]);
        v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE); if (!v) return NGX_ERROR;
        v->get_handler = variable; v->data = i;
    }
    return NGX_OK;
}
static ngx_int_t set_header(ngx_http_request_t *r, const char *name, ngx_str_t value)
{
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *h = part->elts, *new;
    ngx_uint_t i;
    for (i = 0; ; i++) {
        if (i >= part->nelts) { if (!part->next) break; part = part->next; h = part->elts; i = 0; }
        if (h[i].key.len == strlen(name) && !ngx_strncasecmp(h[i].key.data, (u_char *) name, h[i].key.len)) h[i].hash = 0;
    }
    if (!value.len) return NGX_OK;
    new = ngx_list_push(&r->headers_out.headers); if (!new) return NGX_ERROR;
    ngx_memzero(new, sizeof(*new)); new->hash = 1; new->key.data = (u_char *) name; new->key.len = strlen(name); new->value = value;
    return NGX_OK;
}
static ngx_int_t header_filter(ngx_http_request_t *r)
{
    tier_location *conf = ngx_http_get_module_loc_conf(r, ngx_http_scdn_tier_module);
    tier_main *main;
    tier_request *ctx;
    ngx_str_t source = ngx_string("origin"), value, *inner;
    ngx_uint_t code;
    ngx_flag_t store;
    time_t expiry = 0, valid;
    if (!conf->mode) return tier_next_header(r);
    ctx = request_context(r); if (!ctx) return tier_next_header(r);
    main = ngx_http_get_module_main_conf(r, ngx_http_scdn_tier_module);
    code = r->upstream ? r->upstream->cache_status : 0;
    if (ctx->mode == TIER_BACK) {
        if (code == NGX_HTTP_CACHE_HIT || code == NGX_HTTP_CACHE_STALE || code == NGX_HTTP_CACHE_UPDATING || code == NGX_HTTP_CACHE_REVALIDATED) { ngx_str_set(&source, "l2"); }
        if (set_header(r, "X-Tier-Source", source) != NGX_OK) return NGX_ERROR;
        store = !ctx->skip && r->upstream && r->cache && r->headers_out.status == 200
            && r->upstream->cacheable && r->headers_out.content_length_n >= 0
            && r->headers_out.content_length_n <= conf->l2_limit;
        if (store) {
            expiry = r->cache->valid_sec;
            if (ctx->stored_expiry && (!expiry || ctx->stored_expiry < expiry)) expiry = ctx->stored_expiry;
            if (!expiry && (valid = ngx_http_file_cache_valid(r->upstream->conf->cache_valid, 200))) expiry = ngx_time() + valid;
            if (expiry <= ngx_time()) store = 0;
        }
        if (store) { ngx_str_set(&value, "1"); } else { ngx_str_set(&value, "0"); }
        if (set_header(r, "X-Tier-Store", value) != NGX_OK) return NGX_ERROR;
        value.data = ngx_pnalloc(r->pool, 32); if (!value.data) return NGX_ERROR;
        if (store) value.len = ngx_sprintf(value.data, "@%T", expiry) - value.data;
        else { value.data[0] = '0'; value.len = 1; }
        if (set_header(r, "X-Accel-Expires", value) != NGX_OK) return NGX_ERROR;
    } else {
        if (ctx->skip) { ngx_str_set(&source, "off"); }
        else if (code == NGX_HTTP_CACHE_HIT || code == NGX_HTTP_CACHE_STALE || code == NGX_HTTP_CACHE_UPDATING || code == NGX_HTTP_CACHE_REVALIDATED) { ngx_str_set(&source, "l1"); }
        else if (r->upstream && (inner = find_header(&r->upstream->headers_in.headers, "X-Tier-Source")) && same(*inner, "l2")) { ngx_str_set(&source, "l2"); }
        if (!ctx->recorded) {
            ctx->recorded = 1;
            if (same(source, "l1")) ngx_atomic_fetch_add(&main->shared->l1_hits, 1);
            else if (same(source, "l2")) ngx_atomic_fetch_add(&main->shared->l2_hits, 1);
            else if (ctx->skip) ngx_atomic_fetch_add(&main->shared->bypasses, 1);
            else ngx_atomic_fetch_add(&main->shared->origin_reads, 1);
        }
        if (set_header(r, "X-Cache-Layer", source) != NGX_OK) return NGX_ERROR;
        if (ctx->skip) { ngx_str_set(&value, "BYPASS"); }
        else if (same(source, "l2")) { ngx_str_set(&value, "HIT"); }
        else if (code > 0 && code <= 7) value = ngx_http_cache_status[code - 1];
        else { ngx_str_set(&value, "MISS"); }
        if (set_header(r, "X-Cache", value) != NGX_OK) return NGX_ERROR;
        ngx_str_null(&value);
        if (set_header(r, "X-Tier-Source", value) != NGX_OK || set_header(r, "X-Tier-Store", value) != NGX_OK
            || set_header(r, "X-Accel-Expires", value) != NGX_OK) return NGX_ERROR;
    }
    return tier_next_header(r);
}
static ngx_int_t status_handler(ngx_http_request_t *r)
{
    tier_main *main = ngx_http_get_module_main_conf(r, ngx_http_scdn_tier_module);
    ngx_buf_t *buffer; ngx_chain_t chain; ngx_int_t rc;
    if (!local_socket(r)) return NGX_HTTP_FORBIDDEN;
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    if (r->args.len || r->headers_in.content_length_n > 0 || r->headers_in.chunked) return NGX_HTTP_BAD_REQUEST;
    if (!main->shared) return NGX_HTTP_SERVICE_UNAVAILABLE;
    buffer = ngx_create_temp_buf(r->pool, 512); if (!buffer) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    buffer->last = ngx_snprintf(buffer->last, 512,
        "{\"version\":\"0.1.0\",\"l1_hits\":%uA,\"l2_hits\":%uA,\"origin_reads\":%uA,\"bypasses\":%uA,\"lua_required\":false}\n",
        main->shared->l1_hits, main->shared->l2_hits, main->shared->origin_reads, main->shared->bypasses);
    r->headers_out.status = 200; r->headers_out.content_length_n = buffer->last - buffer->pos;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    buffer->last_buf = 1; chain.buf = buffer; chain.next = NULL;
    rc = ngx_http_send_header(r); if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &chain);
}
static ngx_int_t configure(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *core = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *handler = ngx_array_push(&core->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (!handler) return NGX_ERROR;
    *handler = access_handler;
    tier_next_header = ngx_http_top_header_filter; ngx_http_top_header_filter = header_filter;
    return NGX_OK;
}
