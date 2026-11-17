#include "scdn_bot.h"
#include "scdn_security.h"

enum { BOT_CONTINUE, BOT_OBSERVE, BOT_DENY, BOT_INVALID, BOT_WOULD_DENY, BOT_ACTIONS };
enum { BOT_TOKEN, BOT_PHRASE, BOT_EXACT, BOT_PREFIX, BOT_CONTAINS };
typedef struct {
    ngx_str_t id, category, site, feed;
    ngx_uint_t action;
    time_t checked, age;
    ngx_radix_tree_t *v4, *v6;
} bot_entry;
typedef struct { ngx_str_t value; ngx_uint_t entry, type, next; } bot_pattern;
typedef struct { uint16_t next[128], fail, output, dict; } bot_node;
typedef struct { ngx_uint_t magic; ngx_atomic_t actions[BOT_ACTIONS]; } bot_shared;
typedef struct {
    ngx_array_t *entries, *patterns, *proxies;
    bot_node *nodes;
    ngx_uint_t node_count;
    ngx_uint_t prefix_count;
    ngx_flag_t edge_available;
    ngx_flag_t configured;
    ngx_shm_zone_t *zone;
    bot_shared *shared;
} bot_main;
typedef struct { ngx_flag_t enabled; ngx_uint_t mode; size_t ua_limit; } bot_location;
typedef struct {
    ngx_http_request_t *owner;
    ngx_int_t result;
    ngx_uint_t action;
    ngx_str_t id, category, source, match, client, identity;
} bot_request;

static void *bot_create_main(ngx_conf_t *);
static void *bot_create_location(ngx_conf_t *);
static char *bot_merge(ngx_conf_t *, void *, void *);
static char *bot_rule(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_ua(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_ip(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_feed(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_proxy(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_zone(ngx_conf_t *, ngx_command_t *, void *);
static char *bot_status_directive(ngx_conf_t *, ngx_command_t *, void *);
static ngx_int_t bot_preconfiguration(ngx_conf_t *);
static ngx_int_t bot_postconfiguration(ngx_conf_t *);
static ngx_int_t bot_variable(ngx_http_request_t *, ngx_http_variable_value_t *, uintptr_t);
static ngx_int_t bot_status(ngx_http_request_t *);
static ngx_conf_enum_t bot_modes[] = {
    { ngx_string("enforce"), 1 }, { ngx_string("observe"), 0 }, { ngx_null_string, 0 }
};
#define BOT_LOC (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)
static ngx_command_t bot_commands[] = {
    { ngx_string("scdn_bot"), BOT_LOC|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(bot_location, enabled), NULL },
    { ngx_string("scdn_bot_mode"), BOT_LOC|NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(bot_location, mode), bot_modes },
    { ngx_string("scdn_bot_ua_limit"), BOT_LOC|NGX_CONF_TAKE1, ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET, offsetof(bot_location, ua_limit), NULL },
    { ngx_string("scdn_bot_entry"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      bot_rule, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_ua"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      bot_ua, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_ip"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      bot_ip, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_feed"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE4,
      bot_feed, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_trusted_proxy"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      bot_proxy, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_zone"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      bot_zone, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_bot_status"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      bot_status_directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    ngx_null_command
};
static ngx_http_module_t bot_context = {
    bot_preconfiguration, bot_postconfiguration, bot_create_main, NULL,
    NULL, NULL, bot_create_location, bot_merge
};
ngx_module_t ngx_http_scdn_bot_module = {
    NGX_MODULE_V1, &bot_context, bot_commands, NGX_HTTP_MODULE,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NGX_MODULE_V1_PADDING
};
static ngx_str_t action_names[] = {
    ngx_string("continue"), ngx_string("observe"), ngx_string("deny"),
    ngx_string("invalid"), ngx_string("would_deny")
};

static void *bot_create_main(ngx_conf_t *cf) {
    bot_main *m = ngx_pcalloc(cf->pool, sizeof(*m));
    if (!m) return NULL;
    m->entries = ngx_array_create(cf->pool, 16, sizeof(bot_entry));
    m->patterns = ngx_array_create(cf->pool, 32, sizeof(bot_pattern));
    return m->entries && m->patterns ? m : NULL;
}
static void *bot_create_location(ngx_conf_t *cf) {
    bot_location *l = ngx_pcalloc(cf->pool, sizeof(*l));
    if (l) { l->enabled = NGX_CONF_UNSET; l->mode = NGX_CONF_UNSET_UINT; l->ua_limit = NGX_CONF_UNSET_SIZE; }
    return l;
}
static char *bot_merge(ngx_conf_t *cf, void *parent, void *child) {
    bot_location *p = parent, *l = child;
    (void) cf;
    ngx_conf_merge_value(l->enabled, p->enabled, 0);
    ngx_conf_merge_uint_value(l->mode, p->mode, 1);
    ngx_conf_merge_size_value(l->ua_limit, p->ua_limit, 2048);
    if (l->ua_limit < 128 || l->ua_limit > 8192) return "scdn_bot_ua_limit must be 128 to 8192 bytes";
    if (l->enabled) {
        bot_main *m = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_bot_module);
        m->configured = 1;
    }
    return NGX_CONF_OK;
}
static ngx_flag_t equal(ngx_str_t *value, const char *literal) {
    size_t n = ngx_strlen(literal);
    return value->len == n && !ngx_memcmp(value->data, literal, n);
}
static bot_entry *find_entry(bot_main *m, ngx_str_t *id, ngx_uint_t *index) {
    bot_entry *entries = m->entries->elts;
    ngx_uint_t i;
    for (i = 0; i < m->entries->nelts; i++) {
        if (id->len == entries[i].id.len && !ngx_memcmp(id->data, entries[i].id.data, id->len)) {
            if (index) *index = i;
            return &entries[i];
        }
    }
    return NULL;
}
static char *bot_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    bot_entry *e;
    ngx_uint_t action;
    (void) cmd;
    if (!scdn_sec_name(&v[1]) || !scdn_sec_name(&v[2]) || v[2].len > 32
        || (cf->args->nelts == 5 && !scdn_sec_name(&v[4]))) return "invalid scdn_bot_entry name/category/site";
    if (find_entry(m, &v[1], NULL)) return "duplicate scdn_bot_entry ID";
    if (m->entries->nelts >= 256) return "too many scdn_bot_entry rules";
    if (equal(&v[3], "continue")) action = BOT_CONTINUE;
    else if (equal(&v[3], "observe")) action = BOT_OBSERVE;
    else if (equal(&v[3], "deny")) action = BOT_DENY;
    else return "invalid scdn_bot_entry action";
    e = ngx_array_push(m->entries);
    if (!e) return NGX_CONF_ERROR;
    ngx_memzero(e, sizeof(*e));
    e->id = v[1]; e->category = v[2]; e->action = action;
    if (cf->args->nelts == 5) e->site = v[4];
    ngx_str_set(&e->feed, "manual");
    return NGX_CONF_OK;
}
static char *bot_ua(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    ngx_uint_t index, type;
    size_t i;
    bot_pattern *p;
    (void) cmd;
    if (!find_entry(m, &v[1], &index)) return "unknown scdn_bot_ua entry";
    if (!v[3].len || v[3].len > 256 || m->patterns->nelts >= 512) return "scdn_bot_ua pattern/count limit";
    if (equal(&v[2], "token")) type = BOT_TOKEN;
    else if (equal(&v[2], "phrase")) type = BOT_PHRASE;
    else if (equal(&v[2], "exact")) type = BOT_EXACT;
    else if (equal(&v[2], "prefix")) type = BOT_PREFIX;
    else if (equal(&v[2], "contains")) type = BOT_CONTAINS;
    else return "invalid scdn_bot_ua match type";
    for (i = 0; i < v[3].len; i++) if (v[3].data[i] < 32 || v[3].data[i] > 126) return "scdn_bot_ua requires printable ASCII";
    p = ngx_array_push(m->patterns);
    if (!p) return NGX_CONF_ERROR;
    ngx_memzero(p, sizeof(*p)); p->entry = index; p->type = type; p->value = v[3];
    return NGX_CONF_OK;
}
static char *bot_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    bot_entry *e = find_entry(m, &v[1], NULL);
    ngx_cidr_t cidr;
    ngx_int_t rc;
    (void) cmd;
    if (!e) return "unknown scdn_bot_ip entry";
    if (++m->prefix_count > 16384) return "scdn_bot prefix budget exceeded";
    if (scdn_sec_cidr(&v[2], &cidr) != NGX_OK) return "invalid or noncanonical scdn_bot_ip CIDR";
    if (cidr.family == AF_INET) {
        if (!e->v4) e->v4 = ngx_radix_tree_create(cf->pool, -1);
        if (!e->v4) return NGX_CONF_ERROR;
        rc = ngx_radix32tree_insert(e->v4, ntohl(cidr.u.in.addr), ntohl(cidr.u.in.mask), 1);
    } else {
#if (NGX_HAVE_INET6)
        if (!e->v6) e->v6 = ngx_radix_tree_create(cf->pool, -1);
        if (!e->v6) return NGX_CONF_ERROR;
        rc = ngx_radix128tree_insert(e->v6, cidr.u.in6.addr.s6_addr, cidr.u.in6.mask.s6_addr, 1);
#else
        return "IPv6 is unavailable";
#endif
    }
    return rc == NGX_OK || rc == NGX_BUSY ? NGX_CONF_OK : NGX_CONF_ERROR;
}
static char *bot_feed(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    bot_entry *e = find_entry(m, &v[1], NULL);
    time_t checked = ngx_atotm(v[3].data, v[3].len), age = ngx_atotm(v[4].data, v[4].len);
    (void) cmd;
    if (!e || !(equal(&v[2], "manual") || equal(&v[2], "seed") || equal(&v[2], "published") || equal(&v[2], "candidate")))
        return "invalid scdn_bot_feed entry or mode";
    if (checked == (time_t) NGX_ERROR || age == (time_t) NGX_ERROR || age > 2592000)
        return "invalid scdn_bot_feed checked time or maximum age";
    e->feed = v[2]; e->checked = checked; e->age = age;
    return NGX_CONF_OK;
}
static char *bot_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    (void) cmd;
    return scdn_sec_add_proxy(cf, &m->proxies, &v[1]) == NGX_OK ? NGX_CONF_OK : "invalid scdn_bot_trusted_proxy CIDR/count";
}
static ngx_int_t zone_init(ngx_shm_zone_t *zone, void *old) {
    bot_main *m = zone->data, *previous = old;
    ngx_slab_pool_t *slab = (ngx_slab_pool_t *) zone->shm.addr;
    if (previous) m->shared = previous->shared;
    else if (zone->shm.exists) m->shared = slab->data;
    else {
        m->shared = ngx_slab_calloc(slab, sizeof(*m->shared));
        if (!m->shared) return NGX_ERROR;
        m->shared->magic = 0x53424f54; slab->data = m->shared;
    }
    return m->shared && m->shared->magic == 0x53424f54 ? NGX_OK : NGX_ERROR;
}
static char *bot_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    bot_main *m = data;
    ngx_str_t *v = cf->args->elts;
    ssize_t size = ngx_parse_size(&v[2]);
    (void) cmd;
    if (m->zone || size < (ssize_t) (8 * ngx_pagesize) || size > 1048576) return "scdn_bot_zone requires 8 pages to 1m and one zone";
    m->zone = ngx_shared_memory_add(cf, &v[1], size, &ngx_http_scdn_bot_module);
    if (!m->zone) return NGX_CONF_ERROR;
    m->zone->data = m; m->zone->init = zone_init;
    return NGX_CONF_OK;
}
static ngx_flag_t ip_match(bot_entry *e, scdn_sec_ip *ip) {
    if (ip->family == AF_INET && e->v4) {
        in_addr_t address; ngx_memcpy(&address, ip->bytes, 4);
        return ngx_radix32tree_find(e->v4, ntohl(address)) != NGX_RADIX_NO_VALUE;
    }
#if (NGX_HAVE_INET6)
    if (ip->family == AF_INET6 && e->v6)
        return ngx_radix128tree_find(e->v6, ip->bytes) != NGX_RADIX_NO_VALUE;
#endif
    return 0;
}
static ngx_flag_t scoped(bot_entry *e, ngx_str_t *site) {
    return !e->site.len || (e->site.len == site->len && !ngx_memcmp(e->site.data, site->data, site->len));
}
static void request_cleanup(void *data) { (void) data; }
static bot_request *request_context(ngx_http_request_t *r) {
    ngx_pool_cleanup_t *p;
    bot_request *ctx = ngx_http_get_module_ctx(r, ngx_http_scdn_bot_module);
    if (ctx && ctx->owner == r) return ctx;
    for (p = r->pool->cleanup; p; p = p->next) if (p->handler == request_cleanup && ((bot_request *)p->data)->owner == r) {
        ngx_http_set_ctx(r, p->data, ngx_http_scdn_bot_module); return p->data;
    }
    return NULL;
}
static void annotate(bot_request *ctx, bot_entry *entry, scdn_sec_ip *ip, ngx_flag_t by_ip) {
    ctx->id = entry->id; ctx->category = entry->category;
    if (by_ip) { ngx_str_set(&ctx->match, "ip"); } else { ngx_str_set(&ctx->match, "ua"); }
    if (!entry->v4 && !entry->v6) {
        if (equal(&entry->feed, "candidate")) { ngx_str_set(&ctx->source, "candidate_ua"); }
        else { ngx_str_set(&ctx->source, "ua_only"); }
    } else if (equal(&entry->feed, "published") && (!entry->checked || !entry->age ||
        ngx_time() < entry->checked || ngx_time() - entry->checked > entry->age)) {
        ngx_str_set(&ctx->source, "stale");
    } else if (ip_match(entry, ip)) {
        if (equal(&entry->feed, "seed")) { ngx_str_set(&ctx->source, "seed_ip_match"); }
        else { ngx_str_set(&ctx->source, "ip_match"); }
    } else { ngx_str_set(&ctx->source, "ip_mismatch"); }
}
static ngx_flag_t word(u_char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}
static ngx_flag_t pattern_match(bot_pattern *p, ngx_str_t *ua, size_t end) {
    size_t start = end - p->value.len;
    if (p->type == BOT_EXACT) return start == 0 && end == ua->len;
    if (p->type == BOT_PREFIX) return start == 0;
    if (p->type == BOT_CONTAINS) return 1;
    return (!start || !word(ua->data[start - 1])) && (end == ua->len || !word(ua->data[end]));
}

ngx_int_t ngx_http_scdn_bot_check(ngx_http_request_t *r) {
    bot_location *l = ngx_http_get_module_loc_conf(r, ngx_http_scdn_bot_module);
    bot_main *m;
    bot_request *ctx;
    bot_entry *entries, *entry;
    bot_pattern *patterns, *pattern;
    ngx_pool_cleanup_t *cleanup;
    ngx_http_variable_value_t *site_value;
    ngx_str_t site = ngx_null_string, site_name = ngx_string("scdn_edge_site"), ua = ngx_null_string;
    scdn_sec_ip peer, ip;
    ngx_flag_t forwarded, seen_ua = 0;
    ngx_list_part_t *part;
    ngx_table_elt_t *headers;
    ngx_uint_t i, state = 0, output, node, matches = 0;
    size_t offset;
    if (r != r->main) return NGX_DECLINED;
    m = ngx_http_get_module_main_conf(r, ngx_http_scdn_bot_module);
    if (!m->configured) return NGX_DECLINED;
    ctx = request_context(r);
    if (ctx) return ctx->result;
    cleanup = ngx_pool_cleanup_add(r->pool, sizeof(*ctx));
    if (!cleanup) return NGX_HTTP_SERVICE_UNAVAILABLE;
    cleanup->handler = request_cleanup; ctx = cleanup->data;
    ngx_memzero(ctx, sizeof(*ctx)); ctx->owner = r; ctx->result = NGX_DECLINED;
    ngx_str_set(&ctx->id, "unknown"); ngx_str_set(&ctx->category, "unknown");
    ngx_str_set(&ctx->source, "unknown"); ngx_str_set(&ctx->match, "none");
    ngx_str_set(&ctx->identity, "direct");
    ngx_http_set_ctx(r, ctx, ngx_http_scdn_bot_module);
    if (!l->enabled) { ngx_str_set(&ctx->id, "disabled"); return NGX_DECLINED; }
    if (scdn_sec_client(r, m->proxies, &peer, &ip, &forwarded) != NGX_OK) goto invalid;
    ctx->client = scdn_sec_text(r->pool, &ip);
    if (!ctx->client.data) { ctx->result = NGX_HTTP_SERVICE_UNAVAILABLE; return ctx->result; }
    if (forwarded) { ngx_str_set(&ctx->identity, "trusted_xff"); }
    if (m->edge_available) {
        site_value = ngx_http_get_variable(r, &site_name, ngx_hash_key(site_name.data, site_name.len));
        if (site_value && !site_value->not_found) { site.data = site_value->data; site.len = site_value->len; }
    }
    entries = m->entries->elts; patterns = m->patterns->elts;
    for (i = 0; i < m->entries->nelts; i++) {
        entry = &entries[i];
        if (entry->action == BOT_DENY && scoped(entry, &site) && ip_match(entry, &ip)) {
            annotate(ctx, entry, &ip, 1); ctx->action = BOT_DENY; goto finished;
        }
    }
    part = &r->headers_in.headers.part; headers = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) { if (!part->next) break; part = part->next; headers = part->elts; i = 0; }
        if (headers[i].hash && headers[i].key.len == 10 && !ngx_strncasecmp(headers[i].key.data, (u_char *) "User-Agent", 10)) {
            if (seen_ua) goto invalid;
            seen_ua = 1; ua = headers[i].value;
        }
    }
    if (ua.len > l->ua_limit) { ctx->result = 431; goto invalid; }
    for (offset = 0; offset < ua.len; offset++) {
        u_char c = ngx_tolower(ua.data[offset]);
        state = c < 128 ? m->nodes[state].next[c] : 0;
        node = state;
        do {
            output = m->nodes[node].output;
            while (output) {
                if (++matches > 4096) { ctx->result = 431; goto invalid; }
                pattern = &patterns[output - 1]; entry = &entries[pattern->entry];
                if (scoped(entry, &site) && pattern_match(pattern, &ua, offset + 1)) {
                    if (entry->action > ctx->action || equal(&ctx->id, "unknown")) annotate(ctx, entry, &ip, 0);
                    if (entry->action > ctx->action) ctx->action = entry->action;
                    if (ctx->action == BOT_DENY) goto finished;
                }
                output = pattern->next;
            }
            node = m->nodes[node].dict;
        } while (node);
    }
    goto finished;
invalid:
    ctx->action = BOT_INVALID;
    if (ctx->result == NGX_DECLINED) ctx->result = NGX_HTTP_BAD_REQUEST;
finished:
    if (ctx->action == BOT_DENY) ctx->result = NGX_HTTP_FORBIDDEN;
    if (!l->mode && (ctx->action == BOT_DENY || ctx->action == BOT_INVALID)) {
        ctx->action = BOT_WOULD_DENY; ctx->result = NGX_DECLINED;
    }
    if (ctx->result >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_table_elt_t *header = ngx_list_push(&r->headers_out.headers);
        if (!header) { ctx->result = NGX_HTTP_SERVICE_UNAVAILABLE; return ctx->result; }
        ngx_memzero(header, sizeof(*header)); header->hash = 1;
        ngx_str_set(&header->key, "Cache-Control"); ngx_str_set(&header->value, "no-store");
    }
    if (m->shared) ngx_atomic_fetch_add(&m->shared->actions[ctx->action], 1);
    return ctx->result;
}

static ngx_int_t bot_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    bot_request *ctx;
    ngx_str_t *value;
    ctx = request_context(r);
    if (!ctx) { v->not_found = 1; return NGX_OK; }
    switch (data) {
    case 0: value = &ctx->id; break;
    case 1: value = &ctx->category; break;
    case 2: value = &ctx->source; break;
    case 3: value = &action_names[ctx->action]; break;
    case 4: value = &ctx->match; break;
    case 5: value = &ctx->client; break;
    default: value = &ctx->identity; break;
    }
    v->data = value->len ? value->data : (u_char *) ""; v->len = value->len;
    v->valid = 1; v->not_found = 0; v->no_cacheable = 1;
    return NGX_OK;
}
static ngx_int_t bot_preconfiguration(ngx_conf_t *cf) {
    static ngx_str_t names[] = { ngx_string("scdn_bot_id"), ngx_string("scdn_bot_category"),
        ngx_string("scdn_bot_source"), ngx_string("scdn_bot_action"), ngx_string("scdn_bot_match"),
        ngx_string("scdn_bot_client_ip"), ngx_string("scdn_bot_identity") };
    ngx_http_variable_t *v;
    ngx_uint_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        v = ngx_http_add_variable(cf, &names[i], NGX_HTTP_VAR_NOCACHEABLE);
        if (!v) return NGX_ERROR;
        v->get_handler = bot_variable; v->data = i;
    }
    return NGX_OK;
}
static ngx_int_t bot_postconfiguration(ngx_conf_t *cf) {
    bot_main *m = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_bot_module);
    bot_pattern *patterns = m->patterns->elts;
    ngx_uint_t i, state, child, c, maximum = 1, first = 0, last = 0;
    size_t j;
    uint16_t *queue;
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *core;
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->name
            && !ngx_strcmp(cf->cycle->modules[i]->name, "ngx_http_scdn_edge_module")) m->edge_available = 1;
    }
    if (!m->edge_available) {
        bot_entry *entries = m->entries->elts;
        for (i = 0; i < m->entries->nelts; i++) if (entries[i].site.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_bot site scope requires native-edge");
            return NGX_ERROR;
        }
    }
    for (i = 0; i < m->patterns->nelts; i++) maximum += patterns[i].value.len;
    if (maximum > 32768) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_bot automaton exceeds node budget"); return NGX_ERROR; }
    m->nodes = ngx_pcalloc(cf->pool, maximum * sizeof(bot_node));
    queue = ngx_palloc(cf->pool, maximum * sizeof(*queue));
    if (!m->nodes || !queue) return NGX_ERROR;
    m->node_count = 1;
    for (i = 0; i < m->patterns->nelts; i++) {
        state = 0;
        for (j = 0; j < patterns[i].value.len; j++) {
            c = ngx_tolower(patterns[i].value.data[j]);
            if (!m->nodes[state].next[c]) m->nodes[state].next[c] = (uint16_t) m->node_count++;
            state = m->nodes[state].next[c];
        }
        patterns[i].next = m->nodes[state].output;
        m->nodes[state].output = (uint16_t) (i + 1);
    }
    for (c = 0; c < 128; c++) if (m->nodes[0].next[c]) queue[last++] = m->nodes[0].next[c];
    while (first < last) {
        state = queue[first++];
        for (c = 0; c < 128; c++) {
            child = m->nodes[state].next[c];
            if (child) {
                m->nodes[child].fail = m->nodes[m->nodes[state].fail].next[c];
                i = m->nodes[child].fail;
                m->nodes[child].dict = (uint16_t) (m->nodes[i].output ? i : m->nodes[i].dict);
                queue[last++] = (uint16_t) child;
            } else m->nodes[state].next[c] = m->nodes[m->nodes[state].fail].next[c];
        }
    }
    core = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    handler = ngx_array_push(&core->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (!handler) return NGX_ERROR;
    *handler = ngx_http_scdn_bot_check;
    return NGX_OK;
}
static ngx_int_t bot_status(ngx_http_request_t *r) {
    bot_main *m = ngx_http_get_module_main_conf(r, ngx_http_scdn_bot_module);
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t rc;
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) return NGX_HTTP_NOT_ALLOWED;
    b = ngx_create_temp_buf(r->pool, 1024);
    if (!b) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    b->last = ngx_sprintf(b->last, "{\"version\":1,\"rules\":%ui,\"patterns\":%ui,\"nodes\":%ui,\"actions\":[",
        m->entries->nelts, m->patterns->nelts, m->node_count);
    {
        ngx_uint_t i;
        for (i = 0; i < BOT_ACTIONS; i++) b->last = ngx_sprintf(b->last, "%s%uA", i ? "," : "", m->shared ? m->shared->actions[i] : 0);
    }
    b->last = ngx_sprintf(b->last,
        "],\"capabilities\":{\"ua\":true,\"cidr\":true,\"site_scope\":%s,\"automatic_ip_ban\":false,\"sync_resources\":false}}\n",
        m->edge_available ? "true" : "false");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    {
        ngx_table_elt_t *header = ngx_list_push(&r->headers_out.headers);
        if (!header) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_memzero(header, sizeof(*header)); header->hash = 1;
        ngx_str_set(&header->key, "Cache-Control"); ngx_str_set(&header->value, "no-store");
    }
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    b->last_buf = r == r->main; out.buf = b; out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
static char *bot_status_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    ngx_http_core_loc_conf_t *core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    (void) cmd; (void) data;
    if (core->handler) return "scdn_bot_status conflicts with content handler";
    core->handler = bot_status;
    return NGX_CONF_OK;
}
