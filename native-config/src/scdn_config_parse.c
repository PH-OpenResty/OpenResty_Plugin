#include "scdn_config.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

typedef struct {
    char *position, *end;
    ngx_str_t token;
    int symbol;
} scdn_parser_t;

/* Parent and leaf symlinks are rejected. The reader never writes source files. */
static int
scdn_open(const char *path, int directory)
{
    int fd, next;
    char part[256];
    const char *start;
    size_t length;

    if (path == NULL || path[0] != '/' || path[1] == 0) {
        return -1;
    }
    fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    path++;
    while (fd >= 0) {
        start = path;
        while (*path != 0 && *path != '/') { path++; }
        length = path - start;
        if (length == 0 || length > 255
            || (length == 1 && start[0] == '.')
            || (length == 2 && start[0] == '.' && start[1] == '.'))
        {
            close(fd);
            return -1;
        }
        memcpy(part, start, length);
        part[length] = 0;
        next = openat(fd, part, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK
                      |((*path == '/' || directory) ? O_DIRECTORY : 0));
        close(fd);
        fd = next;
        if (*path == 0) { return fd; }
        path++;
    }
    return -1;
}

static u_char *
scdn_read(const char *path, size_t maximum, size_t *length)
{
    int fd;
    struct stat before, after;
    u_char *bytes;
    ssize_t count;
    size_t used = 0;

    fd = scdn_open(path, 0);
    if (fd < 0) { return NULL; }
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0 || (uint64_t) before.st_size > maximum)
    {
        close(fd);
        return NULL;
    }
    bytes = malloc((size_t) before.st_size + 1);
    if (bytes == NULL) { close(fd); return NULL; }
    while (used < (size_t) before.st_size) {
        count = read(fd, bytes + used, (size_t) before.st_size - used);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { free(bytes); close(fd); return NULL; }
        used += (size_t) count;
    }
    if (fstat(fd, &after) != 0 || before.st_size != after.st_size
        || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || memchr(bytes, 0, used) != NULL)
    {
        free(bytes); close(fd); return NULL;
    }
    close(fd);
    bytes[used] = 0;
    *length = used;
    return bytes;
}

static int
scdn_next(scdn_parser_t *p)
{
    char *start, *out;
    int quote;

    p->symbol = 0;
    while (p->position < p->end) {
        if (*p->position == '#') {
            while (p->position < p->end && *p->position != '\n') { p->position++; }
        } else if ((u_char) *p->position <= ' ') { p->position++; }
        else { break; }
    }
    if (p->position == p->end) { p->symbol = -1; return 1; }
    if (strchr("{};", *p->position) != NULL) {
        p->symbol = *p->position++;
        return 1;
    }
    quote = (*p->position == '"' || *p->position == '\'') ? *p->position++ : 0;
    start = out = p->position;
    while (p->position < p->end) {
        if (quote && *p->position == quote) {
            p->position++;
            break;
        }
        if (!quote && ((u_char) *p->position <= ' '
                       || strchr("{};#", *p->position) != NULL)) { break; }
        if (*p->position == '\\') {
            p->position++;
            if (p->position == p->end
                || (*p->position != '\\' && *p->position != '"'
                    && *p->position != '\'')) { return 0; }
        }
        if ((u_char) *p->position < 32) { return 0; }
        *out++ = *p->position++;
        if (out - start > 2048) { return 0; }
    }
    if (quote && (p->position == p->end && p->end[-1] != quote)) { return 0; }
    p->token.data = (u_char *) start;
    p->token.len = out - start;
    if (quote) { *out = 0; }
    return p->token.len != 0;
}

static int
scdn_is(const ngx_str_t *value, const char *literal)
{
    return value->len == strlen(literal)
           && memcmp(value->data, literal, value->len) == 0;
}

static int
scdn_value(scdn_parser_t *p, ngx_str_t *value)
{
    if (!scdn_next(p) || p->symbol != 0) { return 0; }
    *value = p->token;
    return 1;
}

static int
scdn_symbol(scdn_parser_t *p, int symbol)
{
    return scdn_next(p) && p->symbol == symbol;
}

static int
scdn_identifier(ngx_str_t *value)
{
    size_t i;
    u_char c;
    if (value->len == 0 || value->len > 96) { return 0; }
    for (i = 0; i < value->len; i++) {
        c = value->data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || (i != 0 && (c == '_' || c == '-')))) { return 0; }
    }
    return 1;
}

static int
scdn_host(ngx_str_t *value)
{
    size_t i, label = 0;
    u_char c;
    if (value->len == 0 || value->len > 253) { return 0; }
    for (i = 0; i < value->len; i++) {
        c = value->data[i];
        if (c == '.') {
            if (label == 0 || value->data[i - 1] == '-') { return 0; }
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                  || (c == '-' && label != 0))) { return 0; }
            if (++label > 63) { return 0; }
        }
    }
    return label != 0 && value->data[value->len - 1] != '-';
}

static int
scdn_cache(ngx_str_t *value)
{
    return scdn_is(value, "l1") || scdn_is(value, "l2")
           || scdn_is(value, "off") || scdn_is(value, "auto");
}

static int
scdn_upstream(ngx_str_t *value)
{
    size_t i, colon, start;
    ngx_int_t port;
    if (value->len <= 7 || memcmp(value->data, "http://", 7) != 0) { return 0; }
    start = 7;
    colon = value->len;
    for (i = start; i < value->len; i++) {
        if (value->data[i] == ':') {
            if (colon != value->len) { return 0; }
            colon = i;
        }
        else if (!((value->data[i] >= 'a' && value->data[i] <= 'z')
                   || (value->data[i] >= '0' && value->data[i] <= '9')
                   || strchr(".-_", value->data[i]) != NULL)) { return 0; }
    }
    if (colon == start || colon == value->len) { return 0; }
    {
        ngx_str_t host;
        host.data = value->data + start; host.len = colon - start;
        if (!scdn_host(&host)) { return 0; }
    }
    port = ngx_atoi(value->data + colon + 1, value->len - colon - 1);
    return port > 0 && port <= 65535;
}

static int
scdn_path(ngx_str_t *value)
{
    size_t i;
    if (value->len < 2 || value->len > 1024 || value->data[0] != '/') { return 0; }
    for (i = 1; i < value->len; i++) {
        if (value->data[i] < 32 || value->data[i] == '$'
            || value->data[i] == '\\') { return 0; }
    }
    return 1;
}

static char *
scdn_string(ngx_str_t *value)
{
    char *copy = malloc(value->len + 1);
    if (copy != NULL) { memcpy(copy, value->data, value->len); copy[value->len] = 0; }
    return copy;
}

static int
scdn_site(scdn_parser_t *p, scdn_config_site_t *site)
{
    ngx_str_t field, value, second;
    ngx_uint_t fields = 0, flag;
    scdn_config_route_t *route;
    ngx_int_t hits, window;

    site->enabled = 1;
    ngx_str_set(&site->cache, "off");
    if (!scdn_value(p, &site->id) || !scdn_identifier(&site->id)
        || !scdn_symbol(p, '{')) { return 0; }
    while (scdn_next(p) && p->symbol == 0) {
        field = p->token;
        if (scdn_is(&field, "prefix")) {
            if (site->route_count == SCDN_CONFIG_ROUTES) { return 0; }
            route = &site->routes[site->route_count++];
            if (!scdn_value(p, &route->prefix) || !scdn_path(&route->prefix)
                || !scdn_symbol(p, '{')) { return 0; }
            flag = 0;
            while (scdn_next(p) && p->symbol == 0) {
                field = p->token;
                if (!scdn_value(p, &value) || !scdn_symbol(p, ';')) { return 0; }
                if (scdn_is(&field, "upstream") && !(flag & 1) && scdn_upstream(&value)) {
                    route->upstream = value; flag |= 1;
                } else if (scdn_is(&field, "cache") && !(flag & 2) && scdn_cache(&value)) {
                    route->cache = value; flag |= 2;
                } else { return 0; }
            }
            if (p->symbol != '}' || !(flag & 1)) { return 0; }
            continue;
        }
        if (!scdn_value(p, &value)) { return 0; }
        if (scdn_is(&field, "host")) {
            if (site->host_count == SCDN_CONFIG_HOSTS || !scdn_host(&value)) { return 0; }
            site->hosts[site->host_count++] = value;
            flag = 0;
        } else if (scdn_is(&field, "enabled")) {
            if (!scdn_is(&value, "on") && !scdn_is(&value, "off")) { return 0; }
            site->enabled = scdn_is(&value, "on"); flag = 1;
        } else if (scdn_is(&field, "upstream") && scdn_upstream(&value)) {
            site->upstream = value; flag = 2;
        } else if (scdn_is(&field, "root") && scdn_path(&value)) {
            site->root = value; flag = 4;
        } else if (scdn_is(&field, "cache") && scdn_cache(&value)) {
            site->cache = value; flag = 8;
        } else if (scdn_is(&field, "certificate") && scdn_path(&value)) {
            site->certificate = value; flag = 16;
        } else if (scdn_is(&field, "certificate_key") && scdn_path(&value)) {
            site->certificate_key = value; flag = 32;
        } else if (scdn_is(&field, "tier") && scdn_value(p, &second)) {
            hits = ngx_atoi(value.data, value.len);
            window = ngx_atoi(second.data, second.len);
            if (hits <= 0 || hits > 1000000 || window < 100 || window > 86400000) { return 0; }
            site->tier_hits = hits; site->tier_window = window; flag = 64;
        } else { return 0; }
        if ((fields & flag) || !scdn_symbol(p, ';')) { return 0; }
        fields |= flag;
    }
    if (p->symbol != '}' || site->host_count == 0
        || (site->upstream.len == 0 && site->root.len == 0)
        || (site->certificate.len == 0) != (site->certificate_key.len == 0)
        || (scdn_is(&site->cache, "auto") && site->tier_hits == 0)) { return 0; }
    return 1;
}

static int
scdn_same(ngx_str_t *a, ngx_str_t *b)
{
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

static int
scdn_certificates(scdn_config_site_t *site, EVP_MD_CTX *digest, size_t *total,
    const scdn_config_snapshot_t *cache)
{
    char *path;
    u_char *bytes, *private;
    size_t length, private_length, i;
    BIO *bio;
    X509 *certificate;
    char *cursor, *ending;
    size_t block;
    int valid = 0;
    EVP_MD_CTX *material;
    unsigned int material_length;
    ngx_uint_t j;

    if (site->certificate.len == 0 || !site->enabled) { return 1; }
    path = scdn_string(&site->certificate);
    bytes = path != NULL ? scdn_read(path, 262144, &length) : NULL;
    free(path);
    path = scdn_string(&site->certificate_key);
    private = path != NULL ? scdn_read(path, 65536, &private_length) : NULL;
    free(path);
    if (bytes == NULL || private == NULL) { free(bytes); free(private); return 0; }
    *total += length + private_length;
    if (*total > 8 * 1024 * 1024) { goto done; }
    EVP_DigestUpdate(digest, bytes, length);
    EVP_DigestUpdate(digest, private, private_length);
    material = EVP_MD_CTX_new();
    if (material == NULL) { goto done; }
    EVP_DigestInit_ex(material, EVP_sha256(), NULL);
    EVP_DigestUpdate(material, bytes, length);
    EVP_DigestUpdate(material, "\0", 1);
    EVP_DigestUpdate(material, private, private_length);
    EVP_DigestFinal_ex(material, site->material_digest, &material_length);
    EVP_MD_CTX_free(material);
    if (cache != NULL) {
        for (j = 0; j < cache->count; j++) {
            if (cache->sites[j].leaf != NULL
                && memcmp(cache->sites[j].material_digest, site->material_digest, 32) == 0)
            {
                if (!X509_up_ref(cache->sites[j].leaf)) { goto done; }
                site->leaf = cache->sites[j].leaf;
                if (!EVP_PKEY_up_ref(cache->sites[j].key)) { goto done; }
                site->key = cache->sites[j].key;
                site->chain = X509_chain_up_ref(cache->sites[j].chain);
                if (site->chain == NULL) { goto done; }
                goto validate;
            }
        }
    }
    site->chain = sk_X509_new_null();
    if (site->chain == NULL) { goto done; }
    cursor = (char *) bytes;
    while (*cursor != 0) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') { cursor++; }
        if (*cursor == 0) { break; }
        if (strncmp(cursor, "-----BEGIN " "CERTIFICATE-----", 27) != 0) { goto done; }
        ending = strstr(cursor, "-----END CERTIFICATE-----");
        if (ending == NULL) { goto done; }
        block = (size_t) (ending - cursor) + 25;
        bio = BIO_new_mem_buf(cursor, (int) block);
        if (bio == NULL) { goto done; }
        certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (certificate == NULL) { goto done; }
        if (site->leaf == NULL) { site->leaf = certificate; }
        else if (sk_X509_num(site->chain) >= 9 || !sk_X509_push(site->chain, certificate)) {
            X509_free(certificate); goto done;
        }
        cursor += block;
    }
    if (site->leaf == NULL) { goto done; }
    ERR_clear_error();
    bio = BIO_new_mem_buf(private, (int) private_length);
    if (bio == NULL) { goto done; }
    site->key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *) "");
    BIO_free(bio);
validate:
    if (site->key == NULL || X509_check_private_key(site->leaf, site->key) != 1
        || X509_cmp_current_time(X509_get0_notBefore(site->leaf)) > 0
        || X509_cmp_current_time(X509_get0_notAfter(site->leaf)) <= 0) { goto done; }
    for (i = 0; i < site->host_count; i++) {
        path = scdn_string(&site->hosts[i]);
        if (path == NULL) { goto done; }
        valid = X509_check_host(site->leaf, path, 0,
                               X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, NULL) == 1;
        free(path);
        if (!valid) { goto done; }
    }
    valid = 1;
done:
    OPENSSL_cleanse(private, private_length);
    free(private); free(bytes);
    ERR_clear_error();
    return valid;
}

scdn_config_snapshot_t *
scdn_config_load_cached(const char *path, const char **error,
    const scdn_config_snapshot_t *cache)
{
    scdn_config_snapshot_t *snapshot;
    scdn_config_site_t *site;
    scdn_parser_t parser;
    EVP_MD_CTX *digest;
    ngx_uint_t i, j, h, k;
    unsigned int length;
    size_t total;
    char *root;
    int fd;

    *error = "configuration_unavailable";
    snapshot = calloc(1, sizeof(*snapshot));
    digest = EVP_MD_CTX_new();
    if (snapshot == NULL || digest == NULL) { free(snapshot); EVP_MD_CTX_free(digest); return NULL; }
    snapshot->refs = 1;
    snapshot->source = scdn_read(path, SCDN_CONFIG_BYTES, &snapshot->source_size);
    if (snapshot->source == NULL) { goto failed; }
    EVP_DigestInit_ex(digest, EVP_sha256(), NULL);
    EVP_DigestUpdate(digest, snapshot->source, snapshot->source_size);
    total = snapshot->source_size;
    parser.position = (char *) snapshot->source;
    parser.end = parser.position + snapshot->source_size;
    if (!scdn_next(&parser) || parser.symbol != 0
        || !scdn_is(&parser.token, "sites") || !scdn_symbol(&parser, '{')) { goto failed; }
    *error = "invalid_site_configuration";
    while (scdn_next(&parser) && parser.symbol == 0) {
        if (!scdn_is(&parser.token, "site") || snapshot->count == SCDN_CONFIG_SITES) { goto failed; }
        site = &snapshot->sites[snapshot->count++];
        if (!scdn_site(&parser, site)) { goto failed; }
        for (i = 0; i < snapshot->count; i++) {
            if (i + 1 != snapshot->count && scdn_same(&site->id, &snapshot->sites[i].id)) { goto failed; }
            for (h = 0; h < site->host_count; h++) {
                for (k = 0; k < snapshot->sites[i].host_count; k++) {
                    if ((i + 1 != snapshot->count || h != k)
                        && scdn_same(&site->hosts[h], &snapshot->sites[i].hosts[k])) { goto failed; }
                }
            }
        }
        for (i = 0; i < site->route_count; i++) {
            for (j = 0; j < i; j++) {
                if (scdn_same(&site->routes[i].prefix, &site->routes[j].prefix)) { goto failed; }
            }
            if (site->routes[i].cache.len == 0) { site->routes[i].cache = site->cache; }
            if (scdn_is(&site->routes[i].cache, "auto") && site->tier_hits == 0) { goto failed; }
        }
        if (site->enabled && site->root.len != 0) {
            root = scdn_string(&site->root);
            fd = root != NULL ? scdn_open(root, 1) : -1;
            free(root);
            if (fd < 0) { *error = "static_root_unavailable"; goto failed; }
            close(fd);
        }
        if (!scdn_certificates(site, digest, &total, cache)) {
            *error = "certificate_validation_failed"; goto failed;
        }
    }
    if (parser.symbol != '}' || !scdn_next(&parser) || parser.symbol != -1) { goto failed; }
    EVP_DigestFinal_ex(digest, snapshot->digest, &length);
    EVP_MD_CTX_free(digest);
    for (i = 0; i < 32; i++) {
        snapshot->revision[i * 2] = "0123456789abcdef"[snapshot->digest[i] >> 4];
        snapshot->revision[i * 2 + 1] = "0123456789abcdef"[snapshot->digest[i] & 15];
    }
    return snapshot;
failed:
    EVP_MD_CTX_free(digest);
    scdn_config_destroy(snapshot);
    return NULL;
}

scdn_config_snapshot_t *
scdn_config_load(const char *path, const char **error)
{
    return scdn_config_load_cached(path, error, NULL);
}

void
scdn_config_destroy(scdn_config_snapshot_t *snapshot)
{
    ngx_uint_t i;
    if (snapshot == NULL) { return; }
    for (i = 0; i < snapshot->count; i++) {
        X509_free(snapshot->sites[i].leaf);
        sk_X509_pop_free(snapshot->sites[i].chain, X509_free);
        EVP_PKEY_free(snapshot->sites[i].key);
    }
    free(snapshot->source);
    free(snapshot);
}

scdn_config_site_t *
scdn_config_lookup(scdn_config_snapshot_t *snapshot, const ngx_str_t *host)
{
    ngx_uint_t i, j;
    if (snapshot == NULL) { return NULL; }
    for (i = 0; i < snapshot->count; i++) {
        for (j = 0; j < snapshot->sites[i].host_count; j++) {
            if (snapshot->sites[i].hosts[j].len == host->len
                && ngx_strncasecmp(snapshot->sites[i].hosts[j].data,
                                   host->data, host->len) == 0)
            {
                return &snapshot->sites[i];
            }
        }
    }
    return NULL;
}
