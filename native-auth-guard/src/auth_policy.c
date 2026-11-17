#include "auth_internal.h"

static json_object *field(json_object *object, const char *name) {
    json_object *value = NULL;
    (void) json_object_object_get_ex(object, name, &value);
    return value;
}
static ngx_int_t string(ngx_pool_t *pool, json_object *object, const char *name, ngx_str_t *out, size_t maximum) {
    json_object *value = field(object, name);
    const char *text;
    size_t length;
    if (!value || json_object_get_type(value) != json_type_string) return NGX_ERROR;
    length = json_object_get_string_len(value); text = json_object_get_string(value);
    if (!length || length > maximum || ngx_strlen(text) != length) return NGX_ERROR;
    out->data = ngx_pnalloc(pool, length);
    if (!out->data) return NGX_ERROR;
    ngx_memcpy(out->data, text, length); out->len = length;
    return NGX_OK;
}
static int64_t number(json_object *object, const char *name, int64_t fallback, int64_t maximum) {
    json_object *value = field(object, name);
    int64_t result;
    if (!value) return fallback;
    if (json_object_get_type(value) != json_type_int) return -1;
    result = json_object_get_int64(value);
    return result >= 0 && result <= maximum ? result : -1;
}
static ngx_int_t boolean(json_object *object, const char *name, ngx_int_t fallback) {
    json_object *value = field(object, name);
    if (!value) return fallback;
    return json_object_get_type(value) == json_type_boolean ? json_object_get_boolean(value) : NGX_ERROR;
}
json_object *auth_json(const u_char *data, size_t length) {
    json_tokener *parser;
    json_object *result;
    size_t end;
    if (!length || length > (8u << 20)) return NULL;
    parser = json_tokener_new_ex(32);
    if (!parser) return NULL;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    result = json_tokener_parse_ex(parser, (const char *) data, (int) length);
    end = json_tokener_get_parse_end(parser);
    if (json_tokener_get_error(parser) != json_tokener_success) {
        if (result) json_object_put(result);
        result = NULL;
    }
    while (end < length && (data[end] == ' ' || data[end] == '\t' || data[end] == '\r' || data[end] == '\n')) end++;
    if (end != length || !result || json_object_get_type(result) != json_type_object) {
        if (result) json_object_put(result);
        result = NULL;
    }
    json_tokener_free(parser);
    return result;
}
static u_char *read_file(ngx_conf_t *cf, ngx_str_t *name, size_t maximum, size_t *length, ngx_flag_t secret) {
    u_char *path = ngx_pnalloc(cf->pool, name->len + 1), *data;
    int fd;
    struct stat info;
    size_t offset = 0;
    ssize_t count;
    if (!path) return NULL;
    ngx_memcpy(path, name->data, name->len); path[name->len] = 0;
    fd = open((char *) path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 1
        || (uint64_t) info.st_size > maximum || (secret && (info.st_mode & 077))) {
        close(fd); return NULL;
    }
    data = ngx_alloc((size_t) info.st_size + 1, cf->log);
    if (!data) { close(fd); return NULL; }
    while (offset < (size_t) info.st_size) {
        count = read(fd, data + offset, (size_t) info.st_size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { OPENSSL_cleanse(data, offset); ngx_free(data); close(fd); return NULL; }
        offset += (size_t) count;
    }
    close(fd); data[offset] = 0; *length = offset;
    return data;
}
static ngx_int_t unhex(const u_char *text, size_t length, u_char *out) {
    size_t i;
    if (length % 2) return NGX_ERROR;
    for (i = 0; i < length; i += 2) {
        ngx_int_t value = ngx_hextoi((u_char *) text + i, 2);
        if (value == NGX_ERROR) return NGX_ERROR;
        out[i / 2] = (u_char) value;
    }
    return NGX_OK;
}
ngx_int_t auth_secret(ngx_conf_t *cf, ngx_str_t *name, u_char *out) {
    size_t length = 0;
    u_char *data = read_file(cf, name, 66, &length, 1);
    ngx_int_t rc = NGX_ERROR;
    ngx_uint_t i, nonzero = 0;
    if (!data) return NGX_ERROR;
    if (length == 32) { ngx_memcpy(out, data, 32); rc = NGX_OK; }
    else {
        if (length && data[length - 1] == '\n') length--;
        if (length && data[length - 1] == '\r') length--;
        if (length == 64) rc = unhex(data, length, out);
    }
    for (i = 0; i < 32; i++) nonzero |= out[i];
    OPENSSL_cleanse(data, length); ngx_free(data);
    return rc == NGX_OK && nonzero ? NGX_OK : NGX_ERROR;
}
static ngx_int_t domains(ngx_conf_t *cf, json_object *object, const char *name, ngx_array_t **output) {
    json_object *array = field(object, name), *item;
    ngx_str_t *entry;
    const char *text;
    size_t i, j, length;
    if (!array || json_object_get_type(array) != json_type_array || json_object_array_length(array) > 4096) return NGX_ERROR;
    *output = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (!*output) return NGX_ERROR;
    for (i = 0; i < json_object_array_length(array); i++) {
        item = json_object_array_get_idx(array, i);
        if (json_object_get_type(item) != json_type_string) return NGX_ERROR;
        text = json_object_get_string(item); length = json_object_get_string_len(item);
        if (!length || length > 253 || ngx_strlen(text) != length) return NGX_ERROR;
        for (j = 0; j < length; j++) {
            u_char c = (u_char) text[j];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                  || (j == 0 && c == '*'))) return NGX_ERROR;
        }
        if (text[0] == '*' && (length < 3 || text[1] != '.')) return NGX_ERROR;
        entry = ngx_array_push(*output);
        if (!entry) return NGX_ERROR;
        entry->len = length; entry->data = ngx_pnalloc(cf->pool, length);
        if (!entry->data) return NGX_ERROR;
        ngx_memcpy(entry->data, text, length);
    }
    return NGX_OK;
}
static void clear_keys(void *data) {
    auth_main *m = data;
    ngx_uint_t i;
    for (i = 0; i < AUTH_REALMS; i++) OPENSSL_cleanse(m->realms[i].key, 32);
    OPENSSL_cleanse(m->admin_key, 32);
}
ngx_int_t auth_load_policy(ngx_conf_t *cf, auth_main *m, ngx_str_t *path) {
    size_t length = 0, i, j, tag_length = 0;
    u_char *raw = read_file(cf, path, 8u << 20, &length, 0), tag[AUTH_REALMS * 97];
    json_object *root, *realms, *item, *limits, *proxies;
    ngx_str_t key_file, weak_file, proxy;
    auth_realm *r;
    ngx_pool_cleanup_t *cleanup;
    int64_t n;
    if (!raw) return NGX_ERROR;
    root = auth_json(raw, length); ngx_free(raw);
    if (!root) return NGX_ERROR;
    if (number(root, "version", 0, 1) != 1 || string(cf->pool, root, "node_id", &m->node_id, 64) != NGX_OK
        || !scdn_sec_name(&m->node_id)) goto failed;
    realms = field(root, "realms");
    if (!realms || json_object_get_type(realms) != json_type_array || !json_object_array_length(realms)
        || json_object_array_length(realms) > AUTH_REALMS) goto failed;
    cleanup = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cleanup) goto failed;
    cleanup->handler = clear_keys; cleanup->data = m;
    m->realm_count = json_object_array_length(realms);
    for (i = 0; i < m->realm_count; i++) {
        r = &m->realms[i]; item = json_object_array_get_idx(realms, i);
        if (string(cf->pool, item, "id", &r->id, 64) != NGX_OK || !scdn_sec_name(&r->id)
            || string(cf->pool, item, "adapter", &r->adapter, 16) != NGX_OK
            || (!(r->adapter.len == 7 && !ngx_memcmp(r->adapter.data, "sub2api", 7))
               && !(r->adapter.len == 6 && !ngx_memcmp(r->adapter.data, "newapi", 6)))) goto failed;
        for (j = 0; j < i; j++) if (r->id.len == m->realms[j].id.len && !ngx_memcmp(r->id.data, m->realms[j].id.data, r->id.len)) goto failed;
        if (string(cf->pool, item, "key_file", &key_file, NGX_MAX_PATH) != NGX_OK || auth_secret(cf, &key_file, r->key) != NGX_OK
            || string(cf->pool, item, "revision", &r->revision, 96) != NGX_OK || !scdn_sec_name(&r->revision)
            || domains(cf, item, "allowed_domains", &r->allowed) != NGX_OK
            || domains(cf, item, "denied_domains", &r->denied) != NGX_OK) goto failed;
        r->registration = boolean(item, "registration_enabled", 1);
        r->email_verify = boolean(item, "email_verify_enabled", 0);
        r->strict = boolean(item, "strict_email", 1);
        r->precreate = boolean(item, "precreate_required", 1);
        r->alias_restriction = boolean(item, "email_alias_restriction", 0);
        if (r->registration < 0 || r->email_verify < 0 || r->strict < 0 || r->precreate < 0 || r->alias_restriction < 0) goto failed;
        if (!r->strict || !r->precreate) goto failed;
        for (j = 0; j < i; j++) if (!CRYPTO_memcmp(r->key, m->realms[j].key, 32)) goto failed;
        n = number(item, "checked_at", 0, INT64_MAX); if (n < 0) goto failed; r->checked = (time_t) n;
        n = number(item, "max_age", 1800, 86400); if (n < 1) goto failed; r->max_age = (time_t) n;
        limits = field(item, "limits");
        if (limits && json_object_get_type(limits) != json_type_object) goto failed;
#define AUTH_LIMIT(member, name, fallback, maximum) \
        do { n = limits ? number(limits, name, fallback, maximum) : fallback; \
        if (n < 1) { goto failed; } r->member = (ngx_uint_t) n; } while (0)
        AUTH_LIMIT(rate, "per_minute", 60, 6000);
        AUTH_LIMIT(burst, "burst", 20, 1000);
        AUTH_LIMIT(reject_limit, "registration_rejections", 20, 10000);
        AUTH_LIMIT(distinct_limit, "distinct_subjects", 5, AUTH_UNIQUE);
        AUTH_LIMIT(login_limit, "login_failures", 5, 100);
        AUTH_LIMIT(window, "window_seconds", 300, 3600); r->window *= 1000;
        AUTH_LIMIT(ban_time, "ban_seconds", 600, 3600); r->ban_time *= 1000;
        AUTH_LIMIT(cooldown, "cooldown_seconds", 60, 3600); r->cooldown *= 1000;
#undef AUTH_LIMIT
        tag[tag_length++] = (u_char) r->id.len;
        ngx_memcpy(tag + tag_length, r->id.data, r->id.len); tag_length += r->id.len;
        ngx_memcpy(tag + tag_length, r->key, 32); tag_length += 32;
    }
    if (!SHA256(tag, tag_length, m->key_tag)) goto failed;
    OPENSSL_cleanse(tag, sizeof(tag));
    n = number(root, "max_entries", 65536, 1000000); if (n < 1024) goto failed; m->max_entries = (ngx_uint_t) n;
    n = number(root, "max_inflight", 512, 4096); if (n < 4) goto failed; m->max_active = (ngx_uint_t) n;
    if (field(root, "admin_key_file")) {
        if (string(cf->pool, root, "admin_key_file", &key_file, NGX_MAX_PATH) != NGX_OK || auth_secret(cf, &key_file, m->admin_key) != NGX_OK) goto failed;
        m->admin_ready = 1;
        for (i = 0; i < m->realm_count; i++) if (!CRYPTO_memcmp(m->admin_key, m->realms[i].key, 32)) goto failed;
    }
    proxies = field(root, "trusted_proxies");
    if (proxies) {
        if (json_object_get_type(proxies) != json_type_array || json_object_array_length(proxies) > 1024) goto failed;
        for (i = 0; i < json_object_array_length(proxies); i++) {
            item = json_object_array_get_idx(proxies, i);
            if (json_object_get_type(item) != json_type_string) goto failed;
            proxy.data = (u_char *) json_object_get_string(item); proxy.len = json_object_get_string_len(item);
            if (scdn_sec_add_proxy(cf, &m->proxies, &proxy) != NGX_OK) goto failed;
        }
    }
    if (string(cf->pool, root, "password_file", &weak_file, NGX_MAX_PATH) != NGX_OK) goto failed;
    raw = read_file(cf, &weak_file, 65000000, &length, 0);
    if (!raw || length % 65 || !length) { if (raw) ngx_free(raw); goto failed; }
    m->weak_count = length / 65; m->weak = ngx_pnalloc(cf->pool, m->weak_count * 32);
    if (!m->weak) { ngx_free(raw); goto failed; }
    for (i = 0; i < m->weak_count; i++) {
        if (raw[i * 65 + 64] != '\n' || unhex(raw + i * 65, 64, m->weak + i * 32) != NGX_OK
            || (i && ngx_memcmp(m->weak + (i - 1) * 32, m->weak + i * 32, 32) >= 0)) {
            ngx_free(raw); goto failed;
        }
    }
    ngx_free(raw); json_object_put(root); m->policy_loaded = 1;
    return NGX_OK;
failed:
    OPENSSL_cleanse(tag, sizeof(tag)); json_object_put(root);
    return NGX_ERROR;
}
ngx_int_t auth_hmac(auth_realm *realm, const char *purpose, const u_char *data, size_t length, u_char *out) {
    u_char input[32768];
    size_t prefix = ngx_strlen(purpose);
    unsigned int size = 0;
    ngx_int_t result;
    if (prefix + length + 1 > sizeof(input)) return NGX_ERROR;
    ngx_memcpy(input, purpose, prefix); input[prefix++] = ':';
    if (length) ngx_memcpy(input + prefix, data, length);
    result = HMAC(EVP_sha256(), realm->key, 32, input, prefix + length, out, &size) && size == 32 ? NGX_OK : NGX_ERROR;
    OPENSSL_cleanse(input, prefix + length);
    return result;
}
ngx_int_t auth_subject(auth_realm *realm, ngx_str_t *value, u_char *out) {
    return auth_hmac(realm, "subject", value->data, value->len, out);
}
static ngx_flag_t domain_match(ngx_str_t *domain, ngx_str_t *pattern, ngx_flag_t subdomains) {
    if (pattern->len > 2 && pattern->data[0] == '*' && pattern->data[1] == '.') {
        pattern->data += 2; pattern->len -= 2; subdomains = 1;
    }
    if (domain->len == pattern->len && !ngx_memcmp(domain->data, pattern->data, domain->len)) return 1;
    return subdomains && domain->len > pattern->len && domain->data[domain->len - pattern->len - 1] == '.'
        && !ngx_memcmp(domain->data + domain->len - pattern->len, pattern->data, pattern->len);
}
ngx_flag_t auth_domain(auth_realm *realm, ngx_str_t *domain) {
    ngx_str_t *entries = realm->denied->elts, candidate;
    ngx_uint_t i;
    for (i = 0; i < realm->denied->nelts; i++) { candidate = entries[i]; if (domain_match(domain, &candidate, 1)) return 0; }
    entries = realm->allowed->elts;
    for (i = 0; i < realm->allowed->nelts; i++) { candidate = entries[i]; if (domain_match(domain, &candidate, 0)) return 1; }
    return 0;
}
ngx_flag_t auth_weak(auth_main *m, const u_char *value, size_t length) {
    u_char digest[32];
    size_t first = 0, last = m->weak_count, middle;
    ngx_int_t compared;
    ngx_flag_t found = 0;
    if (!m->weak || !SHA256(value, length, digest)) return NGX_ERROR;
    while (first < last) {
        middle = first + (last - first) / 2;
        compared = ngx_memcmp(digest, m->weak + middle * 32, 32);
        if (!compared) { found = 1; break; }
        if (compared < 0) last = middle; else first = middle + 1;
    }
    OPENSSL_cleanse(digest, sizeof(digest)); return found;
}
