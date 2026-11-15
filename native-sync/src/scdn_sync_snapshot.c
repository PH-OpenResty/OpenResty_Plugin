/* Compile the shared data grammar under private symbols: Sync remains loadable
 * without Config, and never parses site data using a second, weaker grammar. */
#define scdn_config_load scdn_sync_snapshot_load
#define scdn_config_load_cached scdn_sync_snapshot_load_cached
#define scdn_config_destroy scdn_sync_snapshot_destroy
#define scdn_config_lookup scdn_sync_snapshot_lookup
#include "../../native-config/src/scdn_config_parse.c"
#define scdn_config_recover scdn_sync_recover
#include "../../native-config/src/scdn_config_transaction.c"
#include "scdn_sync_snapshot.h"

int scdn_sync_safe_open(const char *path, int directory) { return scdn_open(path, directory); }

u_char *scdn_sync_read_file(const char *path, size_t limit, size_t *length, int private_file)
{
    struct stat st;
    int fd = scdn_open(path, 0);
    u_char *bytes;
    size_t total = 0;
    ssize_t n;
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0
        || (uint64_t) st.st_size > limit || (private_file && (st.st_mode & 077))) {
        close(fd); return NULL;
    }
    bytes = malloc((size_t) st.st_size + 1);
    if (!bytes) { close(fd); return NULL; }
    while (total < (size_t) st.st_size) {
        n = read(fd, bytes + total, (size_t) st.st_size - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(bytes); close(fd); return NULL; }
        total += (size_t) n;
    }
    bytes[total] = 0; *length = total; close(fd); return bytes;
}

int scdn_sync_write_file(int directory, const char *name, const void *bytes, size_t length)
{
    char temporary[160];
    struct timespec now;
    size_t done = 0;
    ssize_t n;
    int fd, ok = 0;
    if (strlen(name) > 100 || strchr(name, '/')) return 0;
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(temporary, sizeof(temporary), ".%s.%ld.%ld", name, (long) getpid(), now.tv_nsec);
    fd = openat(directory, temporary, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    while (done < length) {
        n = write(fd, (const u_char *) bytes + done, length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto finish;
        done += (size_t) n;
    }
    if (!fsync(fd) && !renameat(directory, temporary, directory, name) && !fsync(directory)) ok = 1;
finish:
    close(fd); unlinkat(directory, temporary, 0); return ok;
}

void scdn_sync_digest(const void *bytes, size_t length, u_char digest[32])
{
    unsigned n = 0;
    if (EVP_Digest(bytes, length, digest, &n, EVP_sha256(), NULL) != 1 || n != 32)
        memset(digest, 0, 32);
}

typedef struct { u_char *bytes; size_t used, size; int failed; } snapshot_output;
static void put(snapshot_output *out, const void *bytes, size_t n)
{
    if (out->failed || n > out->size - out->used) { out->failed = 1; return; }
    memcpy(out->bytes + out->used, bytes, n); out->used += n;
}
static void literal(snapshot_output *out, const char *value) { put(out, value, strlen(value)); }
static void quoted(snapshot_output *out, ngx_str_t value)
{
    size_t i;
    literal(out, "\"");
    for (i = 0; i < value.len; i++) {
        if (value.data[i] == '"' || value.data[i] == '\\') literal(out, "\\");
        put(out, value.data + i, 1);
    }
    literal(out, "\"");
}
static void field(snapshot_output *out, const char *name, ngx_str_t value)
{
    if (!value.len) return;
    literal(out, name); literal(out, " "); quoted(out, value); literal(out, ";\n");
}
static void headers(snapshot_output *out, scdn_config_headers_t *h, ngx_flag_t enabled)
{
    ngx_uint_t i;
    literal(out, enabled ? "cache_headers on;\n" : "cache_headers off;\n");
    if (h->configured && !h->count) literal(out, "cache_request_headers off;\n");
    for (i = 0; i < h->count; i++) {
        literal(out, "cache_request_header "); quoted(out, h->fields[i].name);
        literal(out, " "); quoted(out, h->fields[i].value); literal(out, ";\n");
    }
}
u_char *scdn_sync_snapshot_export(scdn_config_snapshot_t *snapshot,
    const char *certificate_directory, size_t *size)
{
    snapshot_output out;
    scdn_config_site_t *site;
    scdn_config_route_t *route;
    ngx_uint_t i, j;
    char line[2048];
    out.size = SCDN_CONFIG_BYTES; out.bytes = malloc(out.size); out.used = 0; out.failed = 0;
    if (!out.bytes) return NULL;
    literal(&out, "sites {\n");
    for (i = 0; i < snapshot->count; i++) {
        site = &snapshot->sites[i];
        literal(&out, "site "); quoted(&out, site->id); literal(&out, " {\n");
        for (j = 0; j < site->host_count; j++) field(&out, "host", site->hosts[j]);
        literal(&out, site->enabled ? "enabled on;\n" : "enabled off;\n");
        field(&out, "upstream", site->upstream); field(&out, "root", site->root);
        field(&out, "cache", site->cache); field(&out, "origin_host", site->origin_host);
        headers(&out, &site->cache_request_headers, site->cache_headers);
        if (site->tier_hits) {
            snprintf(line, sizeof(line), "tier %lu %lu;\n", (unsigned long) site->tier_hits,
                     (unsigned long) site->tier_window); literal(&out, line);
        }
        if (site->certificate.len && site->enabled) {
            snprintf(line, sizeof(line), "certificate \"%s/%03lu.crt\";\ncertificate_key \"%s/%03lu.key\";\n",
                certificate_directory, (unsigned long) i, certificate_directory, (unsigned long) i);
            literal(&out, line);
        }
        for (j = 0; j < site->route_count; j++) {
            route = &site->routes[j];
            literal(&out, "prefix "); quoted(&out, route->prefix); literal(&out, " {\n");
            field(&out, "upstream", route->upstream); field(&out, "cache", route->cache);
            field(&out, "origin_host", route->origin_host);
            headers(&out, &route->cache_request_headers, route->cache_headers);
            literal(&out, "}\n");
        }
        literal(&out, "}\n");
    }
    literal(&out, "}\n");
    if (out.failed) { free(out.bytes); return NULL; }
    *size = out.used; return out.bytes;
}
