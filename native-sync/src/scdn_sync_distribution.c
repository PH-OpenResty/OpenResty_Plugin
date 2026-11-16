#include "scdn_sync_module.h"
#include "scdn_sync_bundle.h"
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <sys/file.h>
#include <dirent.h>

#define DIST_LIMIT (SYNC_BUNDLE_MAX + 2048)
#define DIST_STATE 112
typedef struct { ngx_str_t id, path; u_char digest[32]; time_t since; } dist_source;
typedef struct {
    ngx_str_t id, path;
    struct stat verified_file;
    u_char verified_payload[32], verified_binding[32];
    uint64_t verified_sequence, verified_expiry;
} dist_peer_key;
typedef struct { ngx_str_t url; long status; } dist_probe;
typedef struct {
    ngx_str_t directory, signing, trust, decrypt, master, ca, certificate, key, status_socket;
    ngx_array_t sources, keys, probes;
    ngx_flag_t allow_empty;
    ngx_thread_pool_t *threads, *poll_threads;
    ngx_uint_t cursor;
    ngx_msec_t apply_timeout;
    dist_source *cached_source;
    scdn_config_snapshot_t *cached_snapshot;
    u_char *cached_payload;
    size_t cached_length;
} dist_conf;
typedef struct {
    ngx_http_scdn_main_conf_t *main;
    ngx_http_request_t *request;
    ngx_str_t node, scope;
    unsigned operation, status;
    uint64_t sequence;
    u_char digest[32], applied[32];
    char result[32], error[64];
    char conditional[96];
    u_char *body;
    size_t length;
} dist_job;
typedef struct {
    u_char *body;
    size_t length, limit;
    size_t capacity;
    int dynamic;
    char revision[65], managed[65];
    int ready;
} dist_response;
static ngx_event_t dist_timer;
static ngx_thread_task_t *dist_task;
static ngx_http_scdn_main_conf_t *dist_main;

ngx_flag_t scdn_sync_distribution_health(ngx_http_scdn_main_conf_t *main)
{
    dist_conf *conf = main->distribution;
    return conf && main->role == SCDN_SYNC_NODE && conf->probes.nelts != 0;
}

static int equal(const ngx_str_t *value, const char *text)
{ return value->len == strlen(text) && !memcmp(value->data, text, value->len); }
static void hex(const u_char in[32], char out[65])
{
    unsigned i;
    for (i = 0; i < 32; i++) { out[i*2] = "0123456789abcdef"[in[i]>>4]; out[i*2+1] = "0123456789abcdef"[in[i]&15]; }
    out[64] = 0;
}
static int directory_open(const char *path)
{
    struct stat st;
    int fd = scdn_sync_safe_open(path, 1);
    if (fd >= 0 && (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 077))) { close(fd); return -1; }
    return fd;
}
static int lock_directory(int dir, const char *name)
{
    struct stat st;
    int fd = openat(dir, name, O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077)
        || st.st_nlink != 1 || flock(fd, LOCK_EX|LOCK_NB)) { close(fd); return -1; }
    return fd;
}
static int child_directory(int root, const ngx_str_t *id)
{
    char name[97];
    int fd;
    struct stat st;
    if (!scdn_sync_valid_id(id->data, id->len)) return -1;
    memcpy(name, id->data, id->len); name[id->len] = 0;
    if (mkdirat(root, name, 0700) && errno != EEXIST) return -1;
    fd = openat(root, name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd >= 0 && (fstat(fd, &st) || (st.st_mode & 077) || st.st_uid != geteuid() || fsync(root))) {
        close(fd); fd = -1;
    }
    return fd;
}
static u_char *read_at(int root, const char *name, size_t max, size_t *length)
{
    struct stat st;
    u_char *bytes = NULL;
    int fd = openat(root, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    size_t used = 0;
    ssize_t n;
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077)
        || st.st_size < 0 || (uint64_t) st.st_size > max) { errno = EINVAL; goto finish; }
    bytes = malloc((size_t) st.st_size + 1); if (!bytes) goto finish;
    while (used < (size_t) st.st_size) {
        n = read(fd, bytes + used, (size_t) st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(bytes); bytes = NULL; errno = EIO; goto finish; }
        used += (size_t) n;
    }
    bytes[used] = 0; *length = used;
finish:
    close(fd); return bytes;
}
static int state_read(int dir, const char *name, u_char state[DIST_STATE])
{
    size_t n;
    u_char *bytes, hash[32];
    bytes = read_at(dir, name, DIST_STATE, &n);
    if (!bytes) return errno == ENOENT ? 0 : -1;
    scdn_sync_digest(bytes, n == DIST_STATE ? DIST_STATE - 32 : n, hash);
    if (n != DIST_STATE || memcmp(bytes, "SCNDST02", 8) || memcmp(hash, bytes + 80, 32)) {
        free(bytes); return -1;
    }
    memcpy(state, bytes, DIST_STATE); free(bytes); return 1;
}
static int state_write(int dir, const char *name, uint64_t sequence,
    const u_char digest[32], const u_char revision[32])
{
    u_char state[DIST_STATE];
    memcpy(state, "SCNDST02", 8); scdn_sync_put64(state + 8, sequence);
    memcpy(state + 16, digest, 32); memcpy(state + 48, revision, 32);
    scdn_sync_digest(state, 80, state + 80);
    return scdn_sync_write_file(dir, name, state, sizeof(state));
}
static int status_write(int dir, const char *state, const char *error,
    uint64_t sequence, const u_char *revision, int health)
{
    char json[768], digest[65] = "";
    int n;
    size_t previous_length;
    u_char *previous;
    if (revision) hex(revision, digest);
    n = snprintf(json, sizeof(json),
        "{\"ok\":true,\"version\":\"0.3.0\",\"config_protocol\":\"native.snapshot.v2\","
        "\"sync_state\":\"%s\",\"sequence\":\"%llu\",\"applied_revision\":%s%s%s,"
        "\"business_health\":\"%s\",\"last_error\":\"%s\",\"restarts_workers\":false}\n",
        state, (unsigned long long) sequence, revision ? "\"" : "", revision ? digest : "null",
        revision ? "\"" : "", health > 0 ? "passed" : health < 0 ? "failed" : "unknown", error);
    if (n > 0 && (size_t) n < sizeof(json)) {
        previous = read_at(dir, "status.json", sizeof(json), &previous_length);
        if (previous && previous_length == (size_t) n && !memcmp(previous, json, previous_length)) {
            free(previous); return 1;
        }
        free(previous); return scdn_sync_write_file(dir, "status.json", json, (size_t) n);
    }
    return 0;
}

/* Payload: magic, canonical config length, cert count, original source digest,
 * config bytes, then index/cert length/key length + opaque PEM pairs. */
static u_char *payload_create(dist_source *source, size_t *length, const char **error,
    scdn_config_snapshot_t **loaded)
{
    scdn_config_snapshot_t *snapshot = scdn_sync_snapshot_load((char *) source->path.data, error);
    u_char *out = NULL, *config = NULL, *cert = NULL, *key = NULL, material[32];
    size_t config_length, cert_length = 0, key_length = 0, used = 56, capacity, needed;
    u_char *grown;
    ngx_uint_t i, count = 0;
    char path[2049];
    EVP_MD_CTX *ctx;
    unsigned material_length;
    if (!snapshot) return NULL;
    /* The relocation sentinel cannot occur in operator supplied data. */
    if (memmem(snapshot->source, snapshot->source_size, "/__sync_bundle__", 16)) goto failed;
    config = scdn_sync_snapshot_export(snapshot, "/__sync_bundle__", &config_length);
    if (!config) goto failed;
    capacity = 56 + config_length;
    if (capacity > SYNC_BUNDLE_MAX) goto failed;
    out = malloc(capacity); if (!out) goto failed;
    memcpy(out, "SNAP0002", 8); scdn_sync_put64(out + 8, config_length);
    memcpy(out + 24, snapshot->digest, 32);
    memcpy(out + used, config, config_length); used += config_length;
    for (i = 0; i < snapshot->count; i++) {
        scdn_config_site_t *site = &snapshot->sites[i];
        if (!site->enabled || !site->certificate.len) continue;
        memcpy(path, site->certificate.data, site->certificate.len); path[site->certificate.len] = 0;
        cert = scdn_sync_read_file(path, 262144, &cert_length, 0);
        memcpy(path, site->certificate_key.data, site->certificate_key.len); path[site->certificate_key.len] = 0;
        key = scdn_sync_read_file(path, 65536, &key_length, 1);
        if (!cert || !key || used + 24 + cert_length + key_length > SYNC_BUNDLE_MAX) goto failed;
        needed = used + 24 + cert_length + key_length;
        if (needed > capacity) {
            capacity = ngx_min(SYNC_BUNDLE_MAX, ngx_max(needed, capacity * 2));
            grown = realloc(out, capacity); if (!grown) goto failed;
            out = grown;
        }
        ctx = EVP_MD_CTX_new(); if (!ctx) goto failed;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); EVP_DigestUpdate(ctx, cert, cert_length);
        EVP_DigestUpdate(ctx, "\0", 1); EVP_DigestUpdate(ctx, key, key_length);
        EVP_DigestFinal_ex(ctx, material, &material_length); EVP_MD_CTX_free(ctx);
        if (material_length != 32 || memcmp(material, site->material_digest, 32)) goto failed;
        scdn_sync_put64(out + used, i); scdn_sync_put64(out + used + 8, cert_length);
        scdn_sync_put64(out + used + 16, key_length); used += 24;
        memcpy(out + used, cert, cert_length); used += cert_length;
        memcpy(out + used, key, key_length); used += key_length;
        free(cert); cert = NULL; OPENSSL_cleanse(key, key_length); free(key); key = NULL; count++;
    }
    scdn_sync_put64(out + 16, count); *length = used;
    free(config); *loaded = snapshot; return out;
failed:
    *error = "snapshot_material_changed_or_invalid";
    free(cert); if (key) OPENSSL_cleanse(key, key_length); free(key); free(config);
    if (out) OPENSSL_cleanse(out, used);
    free(out); scdn_sync_snapshot_destroy(snapshot); return NULL;
}

static size_t response_body(char *bytes, size_t size, size_t count, void *data)
{
    dist_response *response = data;
    size_t n = size * count;
    u_char *grown;
    size_t capacity;
    if (n > response->limit - response->length) return 0;
    if (response->dynamic && response->length + n > response->capacity) {
        capacity = response->capacity ? response->capacity * 2 : 4096;
        capacity = ngx_min(response->limit, ngx_max(response->length + n, capacity));
        grown = realloc(response->body, capacity); if (!grown) return 0;
        response->body = grown; response->capacity = capacity;
    }
    if (response->body) memcpy(response->body + response->length, bytes, n);
    response->length += n; return n;
}
static size_t response_header(char *bytes, size_t size, size_t count, void *data)
{
    dist_response *response = data;
    size_t n = size * count, i;
    const char *p = bytes, *end = bytes + n;
    if (n > 18 && !strncasecmp(bytes, "X-Config-Revision:", 18)) {
        p += 18; while (p < end && *p == ' ') p++;
        if (end - p != 66) return n;
        for (i = 0; i < 64; i++) if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return n;
        memcpy(response->revision, p, 64); response->revision[64] = 0;
    }
    if (n == 19 && !strncasecmp(bytes, "X-Config-Ready: 1\r\n", 19)) response->ready = 1;
    if (n == 84 && !strncasecmp(bytes, "X-Config-Managed: ", 18)) {
        for (i = 18; i < 82; i++) if (!((bytes[i] >= '0' && bytes[i] <= '9')
            || (bytes[i] >= 'a' && bytes[i] <= 'f'))) return n;
        memcpy(response->managed, bytes + 18, 64); response->managed[64] = 0;
    }
    return n;
}
static CURL *http_handle(dist_conf *conf, const char *url, int remote, const char *socket,
    struct curl_slist *headers, dist_response *response, int post)
{
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url); curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_PROXY, ""); curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, remote ? 10000L : 3000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (remote) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, conf->ca.data);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, conf->certificate.data);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, conf->key.data);
    }
    if (socket) curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket);
    if (post) { curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ""); curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L); }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_body); curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, response_header); curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
    return curl;
}
static int http(dist_conf *conf, const char *url, int remote, const char *socket,
    struct curl_slist *headers, dist_response *response, int post)
{
    CURL *curl = http_handle(conf, url, remote, socket, headers, response, post);
    CURLcode code;
    long status = 0;
    if (!curl) return 0;
    code = curl_easy_perform(curl); curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl); return code == CURLE_OK ? (int) status : 0;
}
static int active_wait(dist_conf *conf, const u_char digest[32])
{
    char expected[65], managed[65]; u_char managed_hash[32];
    struct timespec pause = {0, 50000000};
    struct timespec now;
    int64_t deadline;
    hex(digest, expected);
    scdn_sync_digest(conf->directory.data, conf->directory.len, managed_hash); hex(managed_hash, managed);
    clock_gettime(CLOCK_MONOTONIC, &now);
    deadline = (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000 + conf->apply_timeout;
    while (!ngx_quit && !ngx_terminate) {
        dist_response response; memset(&response, 0, sizeof(response)); response.limit = 4096;
        if (http(conf, "http://localhost/status", 0, (char *) conf->status_socket.data, NULL, &response, 0) == 200
            && response.ready && !strcmp(response.revision, expected) && !strcmp(response.managed, managed)) return 1;
        nanosleep(&pause, NULL);
        if (pause.tv_nsec < 800000000) pause.tv_nsec *= 2;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000 >= deadline) break;
    }
    return 0;
}
static int probe_business(dist_conf *conf)
{
    dist_probe *probes = conf->probes.elts;
    CURLM *multi;
    CURL *handles[4] = {NULL};
    dist_response responses[4];
    ngx_uint_t indexes[4], next = 0, completed = 0, i;
    CURLMsg *message;
    int running, remaining, ok = 0;
    long status;
    if (!conf->probes.nelts) return 1;
    multi = curl_multi_init(); if (!multi) return 0;
    memset(responses, 0, sizeof(responses));
    while (completed < conf->probes.nelts && !ngx_quit && !ngx_terminate) {
        for (i = 0; i < 4 && next < conf->probes.nelts; i++) if (!handles[i]) {
            indexes[i] = next++;
            memset(&responses[i], 0, sizeof(responses[i])); responses[i].limit = 1048576;
            handles[i] = http_handle(conf, (char *) probes[indexes[i]].url.data, 0, NULL, NULL, &responses[i], 0);
            if (!handles[i] || curl_multi_add_handle(multi, handles[i]) != CURLM_OK) goto finish;
        }
        if (curl_multi_perform(multi, &running) != CURLM_OK) goto finish;
        while ((message = curl_multi_info_read(multi, &remaining)) != NULL) {
            if (message->msg != CURLMSG_DONE) continue;
            for (i = 0; i < 4; i++) if (handles[i] == message->easy_handle) break;
            if (i == 4) goto finish;
            curl_easy_getinfo(handles[i], CURLINFO_RESPONSE_CODE, &status);
            if (message->data.result != CURLE_OK || status != probes[indexes[i]].status) goto finish;
            curl_multi_remove_handle(multi, handles[i]); curl_easy_cleanup(handles[i]); handles[i] = NULL;
            completed++;
        }
        if (completed < conf->probes.nelts && curl_multi_poll(multi, NULL, 0, 100, NULL) != CURLM_OK) goto finish;
    }
    ok = completed == conf->probes.nelts;
finish:
    for (i = 0; i < 4; i++) if (handles[i]) {
        curl_multi_remove_handle(multi, handles[i]); curl_easy_cleanup(handles[i]);
    }
    curl_multi_cleanup(multi); return ok;
}
static int report_result(dist_conf *conf, uint64_t sequence, const u_char digest[32],
    const char *state, const char *error, const u_char *applied)
{
    struct curl_slist *headers = NULL;
    char line[256], url[2304], digest_hex[65];
    dist_response response;
    int result;
    memset(&response, 0, sizeof(response)); response.limit = 4096; hex(digest, digest_hex);
    snprintf(url, sizeof(url), "%s/_scdn_sync/v1/config/result", conf->master.data);
    snprintf(line, sizeof(line), "X-Config-Sequence: %llu", (unsigned long long) sequence); headers = curl_slist_append(headers, line);
    snprintf(line, sizeof(line), "X-Config-Digest: %s", digest_hex); headers = curl_slist_append(headers, line);
    snprintf(line, sizeof(line), "X-Config-State: %s", state); headers = curl_slist_append(headers, line);
    snprintf(line, sizeof(line), "X-Config-Error: %s", error); headers = curl_slist_append(headers, line);
    if (applied) {
        hex(applied, digest_hex); snprintf(line, sizeof(line), "X-Config-Applied: %s", digest_hex);
        headers = curl_slist_append(headers, line);
    }
    result = http(conf, url, 1, NULL, headers, &response, 1) == 200;
    curl_slist_free_all(headers); return result;
}

static u_char *relocate(const u_char *input, size_t length, const char *directory, size_t *size)
{
    static const char marker[] = "/__sync_bundle__";
    size_t i = 0, used = 0, d = strlen(directory), needed = 0, step;
    u_char *output;
    while (i < length) {
        step = i + sizeof(marker) - 1 <= length && !memcmp(input + i, marker, sizeof(marker) - 1);
        needed += step ? d : 1;
        if (needed >= SCDN_CONFIG_BYTES) return NULL;
        i += step ? sizeof(marker) - 1 : 1;
    }
    i = 0;
    output = malloc(needed + 1);
    if (!output) return NULL;
    while (i < length) {
        if (i + sizeof(marker) - 1 <= length && !memcmp(input + i, marker, sizeof(marker) - 1)) {
            if (used + d >= SCDN_CONFIG_BYTES) goto fail;
            memcpy(output + used, directory, d); used += d; i += sizeof(marker) - 1;
        } else {
            if (used + 1 >= SCDN_CONFIG_BYTES || input[i] == 0) goto fail;
            output[used++] = input[i++];
        }
    }
    *size = used; return output;
fail:
    free(output); return NULL;
}
static scdn_config_snapshot_t *stage_payload(dist_conf *conf, int dir, const u_char *plain,
    size_t size, uint64_t sequence, u_char **config, size_t *config_size, const char **error)
{
    uint64_t text_length, count, idx, crt, key;
    size_t offset, i;
    int releases = -1, release = -1;
    char name[64], path[1600], file[32];
    ngx_str_t release_id;
    scdn_config_snapshot_t *snapshot = NULL;
    u_char seen[256] = {0};
    if (size < 56 || memcmp(plain, "SNAP0002", 8)) return NULL;
    text_length = scdn_sync_u64(plain + 8); count = scdn_sync_u64(plain + 16);
    if (!text_length || text_length > SCDN_CONFIG_BYTES || text_length > size - 56 || count > 256) return NULL;
    {
        ngx_str_t folder = ngx_string("releases"); releases = child_directory(dir, &folder);
    }
    if (releases < 0) goto finish;
    snprintf(name, sizeof(name), "r%020llu", (unsigned long long) sequence);
    release_id.data = (u_char *) name; release_id.len = strlen(name);
    release = child_directory(releases, &release_id); if (release < 0) goto finish;
    snprintf(path, sizeof(path), "%s/releases/%s", conf->directory.data, name);
    *config = relocate(plain + 56, (size_t) text_length, path, config_size);
    if (!*config) goto finish;
    offset = 56 + (size_t) text_length;
    for (i = 0; i < count; i++) {
        if (size - offset < 24) goto finish;
        idx = scdn_sync_u64(plain + offset); crt = scdn_sync_u64(plain + offset + 8); key = scdn_sync_u64(plain + offset + 16);
        offset += 24;
        if (idx >= 256 || seen[idx] || !crt || !key || crt > 262144 || key > 65536 || crt + key > size - offset) goto finish;
        seen[idx] = 1;
        snprintf(file, sizeof(file), "%03u.crt", (unsigned) idx);
        if (!scdn_sync_write_file(release, file, plain + offset, (size_t) crt)) goto finish;
        offset += (size_t) crt;
        snprintf(file, sizeof(file), "%03u.key", (unsigned) idx);
        if (!scdn_sync_write_file(release, file, plain + offset, (size_t) key)) goto finish;
        offset += (size_t) key;
    }
    if (offset != size || !scdn_sync_write_file(release, "sites.conf", *config, *config_size)) goto finish;
    snprintf(path, sizeof(path), "%s/releases/%s/sites.conf", conf->directory.data, name);
    snapshot = scdn_sync_snapshot_load(path, error);
    if (snapshot && !snapshot->count && !conf->allow_empty) {
        scdn_sync_snapshot_destroy(snapshot); snapshot = NULL; *error = "empty_configuration";
    }
finish:
    if (release >= 0) close(release);
    if (releases >= 0) close(releases);
    return snapshot;
}

/* Keep releases referenced by either rollback file. Readers hold parsed TLS
 * objects in memory; GC never changes the active or previous source files. */
static void release_gc(int directory)
{
    int fd, child, streamfd;
    DIR *folders = NULL, *files = NULL;
    struct dirent *entry, *file;
    size_t active_size = 0, previous_size = 0, i;
    u_char *active = read_at(directory, "active.conf", SCDN_CONFIG_BYTES, &active_size);
    u_char *previous = read_at(directory, "previous.conf", SCDN_CONFIG_BYTES, &previous_size);
    unsigned budget = 32;
    char name[32];
    if (!active || !previous) goto finish;
    fd = openat(directory, "releases", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) goto finish;
    folders = fdopendir(fd); if (!folders) { close(fd); goto finish; }
    while (budget && (entry = readdir(folders)) != NULL) {
        if (strlen(entry->d_name) != 21 || entry->d_name[0] != 'r') continue;
        for (i = 1; i < 21; i++) if (entry->d_name[i] < '0' || entry->d_name[i] > '9') break;
        if (i != 21 || memmem(active, active_size, entry->d_name, 21)
            || memmem(previous, previous_size, entry->d_name, 21)) continue;
        budget--;
        child = openat(dirfd(folders), entry->d_name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (child < 0) continue;
        streamfd = dup(child); files = streamfd >= 0 ? fdopendir(streamfd) : NULL;
        if (!files) { if (streamfd >= 0) close(streamfd); close(child); continue; }
        while ((file = readdir(files)) != NULL) {
            if (!strcmp(file->d_name, "sites.conf")) { unlinkat(child, file->d_name, 0); continue; }
            if (strlen(file->d_name) != 7 || (strcmp(file->d_name + 3, ".crt") && strcmp(file->d_name + 3, ".key"))) continue;
            for (i = 0; i < 3; i++) if (file->d_name[i] < '0' || file->d_name[i] > '9') break;
            if (i == 3) { memcpy(name, file->d_name, 8); unlinkat(child, name, 0); }
        }
        closedir(files); files = NULL; close(child);
        (void) unlinkat(dirfd(folders), entry->d_name, AT_REMOVEDIR);
    }
    (void) fsync(dirfd(folders)); closedir(folders);
finish:
    free(active); free(previous);
}

static void node_cycle(ngx_http_scdn_main_conf_t *main)
{
    dist_conf *conf = main->distribution;
    int dir = -1, lock = -1, state, result, committed = 0, health = 0;
    size_t length = 0, plain_size = 0, config_size = 0, previous_size = 0;
    uint64_t sequence = 0;
    u_char *envelope = NULL, *plain = NULL, *config = NULL, *previous = NULL;
    u_char highest[DIST_STATE], applied[DIST_STATE], rejected[DIST_STATE], reported[DIST_STATE];
    u_char marker[SCDN_CONFIG_PENDING_BYTES], digest[32], zero[32] = {0};
    scdn_config_snapshot_t *candidate = NULL, *old = NULL;
    EVP_PKEY *verify = NULL, *decrypt = NULL;
    dist_response response;
    struct curl_slist *conditional = NULL;
    char url[2304], active_path[1600], tag[128], hash_text[65];
    const char *error = "configuration_sync_unavailable";
    dir = directory_open((char *) conf->directory.data); if (dir < 0) return;
    lock = lock_directory(dir, "apply.lock"); if (lock < 0) goto finish;
    committed = 1;
    if (!scdn_sync_recover_locked(dir, 1)) { error = "transaction_recovery_failed"; goto failed; }
    committed = 0;
    state = state_read(dir, "applied.state", applied);
    if (state < 0) { error = "applied_state_corrupt"; goto failed; }
    if (!state) memset(applied, 0, sizeof(applied));
    memset(&response, 0, sizeof(response)); response.limit = 4096;
    scdn_sync_digest(conf->directory.data, conf->directory.len, digest); hex(digest, hash_text);
    if (http(conf, "http://localhost/status", 0, (char *) conf->status_socket.data, NULL, &response, 0) != 200
        || strcmp(response.managed, hash_text)) { error = "managed_configuration_mismatch"; goto failed; }
    memset(&response, 0, sizeof(response)); response.dynamic = 1; response.limit = DIST_LIMIT;
    snprintf(url, sizeof(url), "%s/_scdn_sync/v1/config/desired", conf->master.data);
    if (scdn_sync_u64(applied + 8)) {
        hex(applied + 16, hash_text);
        snprintf(tag, sizeof(tag), "If-None-Match: \"%llu-%s\"", (unsigned long long) scdn_sync_u64(applied + 8), hash_text);
        conditional = curl_slist_append(NULL, tag);
    }
    result = http(conf, url, 1, NULL, conditional, &response, 0);
    envelope = response.body;
    curl_slist_free_all(conditional); conditional = NULL;
    if (result == 204) { if (!scdn_sync_u64(applied + 8)) status_write(dir, "waiting_for_publish", "", 0, NULL, 0); goto finish; }
    if (result == 304 && scdn_sync_u64(applied + 8)) {
        sequence = scdn_sync_u64(applied + 8); memcpy(digest, applied + 16, 32);
        state = state_read(dir, "highest.state", highest);
        if (state != 1 || scdn_sync_u64(highest + 8) != sequence || memcmp(highest + 16, digest, 32)) {
            error = "snapshot_replay_or_conflict"; goto failed;
        }
        goto already_applied;
    }
    if (result != 200) { error = "master_unavailable"; goto failed; }
    length = response.length;
    verify = scdn_sync_key_load((char *) conf->trust.data, 0, EVP_PKEY_ED25519);
    decrypt = scdn_sync_key_load((char *) conf->decrypt.data, 1, EVP_PKEY_RSA);
    if (!verify || !decrypt) { error = "snapshot_keys_unavailable"; goto failed; }
    plain = scdn_sync_unseal(envelope, length, &main->id, &main->scope, verify, decrypt, &sequence, &plain_size);
    if (!plain) { error = "snapshot_verification_failed"; goto failed; }
    scdn_sync_digest(plain, plain_size, digest);
    state = state_read(dir, "highest.state", highest);
    if (state < 0) { error = "highest_state_corrupt"; goto failed; }
    if (!state && scdn_sync_u64(applied + 8)) { error = "highest_state_missing"; goto failed; }
    if (sequence < scdn_sync_u64(applied + 8)
        || (sequence == scdn_sync_u64(applied + 8) && memcmp(applied + 16, digest, 32))) {
        error = "snapshot_replay_or_conflict"; goto failed;
    }
    if (state && (sequence < scdn_sync_u64(highest + 8)
        || (sequence == scdn_sync_u64(highest + 8) && memcmp(highest + 16, digest, 32)))) {
        error = "snapshot_replay_or_conflict"; goto failed;
    }
    if (sequence == scdn_sync_u64(applied + 8) && !memcmp(applied + 16, digest, 32)) {
already_applied:
        if (!active_wait(conf, applied + 48)) { error = "applied_runtime_mismatch"; goto failed; }
        state = state_read(dir, "probe.state", reported);
        health = state == 1 && scdn_sync_u64(reported + 8) == sequence && !memcmp(reported + 16, digest, 32) ? 1 : 0;
        status_write(dir, "applied", "", sequence, applied + 48, health);
        state = state_read(dir, "reported.state", reported);
        if (state != 1 || scdn_sync_u64(reported + 8) != sequence || memcmp(reported + 16, digest, 32)) {
            if (report_result(conf, sequence, digest, "applied", "none", applied + 48))
                (void) state_write(dir, "reported.state", sequence, digest, applied + 48);
        }
        goto finish;
    }
    state = state_read(dir, "rejected.state", rejected);
    if (state < 0) { error = "rejected_state_corrupt"; goto failed; }
    if (state == 1 && scdn_sync_u64(rejected + 8) == sequence && !memcmp(rejected + 16, digest, 32)) {
        size_t code_length;
        u_char *code = read_at(dir, "failed.error", 63, &code_length);
        if (code && scdn_sync_valid_id(code, code_length))
            (void) report_result(conf, sequence, digest, "failed", (char *) code,
                                scdn_sync_u64(applied + 8) ? applied + 48 : NULL);
        free(code); goto finish;
    }
    if (!state_write(dir, "highest.state", sequence, digest, zero)) { error = "highest_state_write_failed"; goto failed; }
    candidate = stage_payload(conf, dir, plain, plain_size, sequence, &config, &config_size, &error);
    if (!candidate) {
        if (!strcmp(error, "configuration_sync_unavailable")) error = "snapshot_stage_failed";
        (void) state_write(dir, "rejected.state", sequence, digest, zero); goto failed;
    }
    snprintf(active_path, sizeof(active_path), "%s/active.conf", conf->directory.data);
    old = scdn_sync_snapshot_load(active_path, &error);
    previous = read_at(dir, "active.conf", SCDN_CONFIG_BYTES, &previous_size);
    if (!old || !previous) { error = "previous_configuration_unavailable"; goto failed; }
    if ((scdn_sync_u64(applied + 8) && memcmp(applied + 48, old->digest, 32))
        || !active_wait(conf, old->digest)) { error = "previous_runtime_mismatch"; goto failed; }
    if (!scdn_sync_write_file(dir, "previous.conf", previous, previous_size)) { error = "backup_write_failed"; goto failed; }
    memcpy(marker, "SCNDP02", 8); scdn_sync_digest(previous, previous_size, marker + 8);
    memcpy(marker + 40, applied, DIST_STATE);
    scdn_sync_digest(marker, sizeof(marker) - 32, marker + sizeof(marker) - 32);
    committed = 1;
    if (!scdn_sync_write_file(dir, "apply.pending", marker, sizeof(marker))) { error = "prepare_write_failed"; goto failed; }
    if (!scdn_sync_write_file(dir, "active.conf", config, config_size)) { error = "configuration_commit_failed"; goto rollback; }
    status_write(dir, "applying", "", sequence, scdn_sync_u64(applied + 8) ? applied + 48 : NULL, 0);
    if (!active_wait(conf, candidate->digest)) { error = "worker_apply_timeout"; goto rollback; }
    if (!probe_business(conf)) { error = "business_probe_failed"; health = -1; goto rollback; }
    health = conf->probes.nelts ? 1 : 0;
    if (!state_write(dir, "applied.state", sequence, digest, candidate->digest)) { error = "applied_record_failed"; goto rollback; }
    /* A visible unlink keeps the new durable pair. Recovery reconciles either
     * the surviving marker or its durable absence after a directory I/O error. */
    if (unlinkat(dir, "apply.pending", 0) || fsync(dir)) { error = "finalize_pending"; goto failed; }
    committed = 0;
    if (health) (void) state_write(dir, "probe.state", sequence, digest, candidate->digest);
    status_write(dir, "applied", "", sequence, candidate->digest, health);
    if (report_result(conf, sequence, digest, "applied", "none", candidate->digest))
        (void) state_write(dir, "reported.state", sequence, digest, candidate->digest);
    release_gc(dir);
    goto finish;
rollback:
    if (!scdn_sync_recover_locked(dir, 0) || !active_wait(conf, old->digest)) {
        error = "rollback_pending"; goto failed;
    }
    if (unlinkat(dir, "apply.pending", 0) || fsync(dir)) { error = "rollback_pending"; goto failed; }
    committed = 0;
    (void) state_write(dir, "rejected.state", sequence, digest, zero);
failed:
    state = state_read(dir, "applied.state", applied);
    status_write(dir, committed ? "recovery_required" : "failed", error, sequence,
                 !committed && state == 1 ? applied + 48 : NULL, committed ? 0 : health);
    (void) scdn_sync_write_file(dir, "failed.error", error, strlen(error));
    if (plain && sequence) (void) report_result(conf, sequence, digest, "failed", error, !committed && state == 1 ? applied + 48 : NULL);
finish:
    EVP_PKEY_free(verify); EVP_PKEY_free(decrypt);
    scdn_sync_snapshot_destroy(candidate); scdn_sync_snapshot_destroy(old);
    if (plain) OPENSSL_cleanse(plain, plain_size);
    free(plain); free(envelope); free(config); free(previous);
    if (lock >= 0) close(lock);
    if (dir >= 0) close(dir);
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return S_ISREG(a->st_mode) && !(a->st_mode & 077)
        && a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size
        && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static void master_cycle(ngx_http_scdn_main_conf_t *main)
{
    dist_conf *conf = main->distribution;
    dist_source *sources = conf->sources.elts, *source;
    dist_peer_key *keys = conf->keys.elts;
    ngx_http_scdn_peer_t *peers = main->peers.elts;
    ngx_uint_t i, j;
    EVP_PKEY *sign = NULL, *encrypt = NULL;
    u_char *plain = NULL, *sealed = NULL, *old = NULL, state[DIST_STATE], binding[32], payload_digest[32];
    u_char *der = NULL, *binding_input, signing_public[32];
    size_t signing_length = sizeof(signing_public);
    int der_length;
    struct stat current_file;
    scdn_config_snapshot_t *loaded = NULL;
    dist_peer_key *peer_key;
    size_t size = 0, sealed_size = 0, old_size = 0;
    uint64_t sequence;
    int root = -1, dir = -1, lock = -1, found;
    const char *error = "source_unavailable";
    time_t now = time(NULL);
    if (!conf->sources.nelts) return;
    source = &sources[conf->cursor++ % conf->sources.nelts];
    root = directory_open((char *) conf->directory.data); if (root < 0) return;
    if (source == conf->cached_source && scdn_sync_snapshot_matches((char *) source->path.data, conf->cached_snapshot)) {
        plain = conf->cached_payload; size = conf->cached_length;
    } else {
        plain = payload_create(source, &size, &error, &loaded);
        if (plain) {
            if (conf->cached_payload) OPENSSL_cleanse(conf->cached_payload, conf->cached_length);
            free(conf->cached_payload); scdn_sync_snapshot_destroy(conf->cached_snapshot);
            conf->cached_source = source; conf->cached_snapshot = loaded;
            conf->cached_payload = plain; conf->cached_length = size;
        }
    }
    if (!plain) { status_write(root, "source_rejected", error, 0, NULL, 0); goto finish; }
    if (!conf->allow_empty && size >= 56 && !memcmp(plain + 56, "sites {\n}\n", 10)) {
        status_write(root, "source_rejected", "empty_configuration", 0, NULL, 0); goto finish;
    }
    if (memcmp(source->digest, plain + 24, 32)) { memcpy(source->digest, plain + 24, 32); source->since = now; goto finish; }
    if (now - source->since < 2) goto finish;
    sign = scdn_sync_key_load((char *) conf->signing.data, 1, EVP_PKEY_ED25519);
    if (!sign) { status_write(root, "publish_failed", "signing_key_unavailable", 0, NULL, 0); goto finish; }
    if (EVP_PKEY_get_raw_public_key(sign, signing_public, &signing_length) != 1
        || signing_length != sizeof(signing_public)) goto finish;
    scdn_sync_digest(plain, size, payload_digest);
    for (i = 0; i < main->peers.nelts; i++) {
        if (peers[i].scope.len != source->id.len || memcmp(peers[i].scope.data, source->id.data, source->id.len)) continue;
        for (j = 0; j < conf->keys.nelts; j++) if (keys[j].id.len == peers[i].id.len && !memcmp(keys[j].id.data, peers[i].id.data, peers[i].id.len)) break;
        if (j == conf->keys.nelts) continue;
        peer_key = &keys[j];
        dir = child_directory(root, &peers[i].id); if (dir < 0) continue;
        lock = lock_directory(dir, "publish.lock"); if (lock < 0) { close(dir); dir = -1; continue; }
        found = state_read(dir, "sequence.state", state);
        if (found < 0) { status_write(dir, "publish_failed", "sequence_corrupt", 0, NULL, 0); goto next; }
        encrypt = scdn_sync_key_load((char *) peer_key->path.data, 0, EVP_PKEY_RSA);
        if (!encrypt) goto next;
        der_length = i2d_PUBKEY(encrypt, &der);
        if (der_length <= 0) goto next;
        binding_input = malloc((size_t) der_length + 64);
        if (!binding_input) goto next;
        memcpy(binding_input, der, (size_t) der_length);
        memcpy(binding_input + der_length, peers[i].fingerprint, 32);
        memcpy(binding_input + der_length + 32, signing_public, 32);
        scdn_sync_digest(binding_input, (size_t) der_length + 64, binding);
        free(binding_input); OPENSSL_free(der); der = NULL;
        if (found && peer_key->verified_sequence == scdn_sync_u64(state + 8)
            && peer_key->verified_expiry > (uint64_t) now + 3600
            && !memcmp(peer_key->verified_payload, payload_digest, 32)
            && !memcmp(peer_key->verified_binding, binding, 32)
            && !memcmp(state + 16, payload_digest, 32) && !memcmp(state + 48, binding, 32)
            && !fstatat(dir, "desired.bundle", &current_file, AT_SYMLINK_NOFOLLOW)
            && same_file(&current_file, &peer_key->verified_file)) goto next;
        old = read_at(dir, "desired.bundle", DIST_LIMIT, &old_size);
        if (old && scdn_sync_signature_valid(old, old_size, sign)) {
            /* Recover only from an authenticated local high-water mark. */
            if (!found) {
                if (!state_write(dir, "sequence.state", scdn_sync_u64(old + 8), old + 248, (u_char[32]){0})) goto next;
                found = state_read(dir, "sequence.state", state);
                if (found != 1) goto next;
            }
            if (old[48] == peers[i].id.len && old[49] == peers[i].scope.len
                && !memcmp(old + 56, peers[i].id.data, peers[i].id.len)
                && !memcmp(old + 152, peers[i].scope.data, peers[i].scope.len)
                && scdn_sync_u64(old + 8) == scdn_sync_u64(state + 8)
                && !memcmp(state + 48, binding, 32)
                && !memcmp(old + 248, payload_digest, 32)
                && scdn_sync_u64(old + 24) > (uint64_t) now + 3600) {
                if (!fstatat(dir, "desired.bundle", &peer_key->verified_file, AT_SYMLINK_NOFOLLOW)) {
                    peer_key->verified_sequence = scdn_sync_u64(old + 8);
                    peer_key->verified_expiry = scdn_sync_u64(old + 24);
                    memcpy(peer_key->verified_payload, payload_digest, 32);
                    memcpy(peer_key->verified_binding, binding, 32);
                }
                goto next;
            }
        } else if (!found && (old || errno != ENOENT)) {
            status_write(dir, "publish_failed", "sequence_missing", 0, NULL, 0); goto next;
        }
        sequence = found ? scdn_sync_u64(state + 8) : 0;
        if (sequence == UINT64_MAX) goto next;
        sequence++;
        if (!state_write(dir, "sequence.state", sequence, payload_digest, binding)) goto next;
        sealed = scdn_sync_seal(plain, size, sequence, &peers[i].id, &peers[i].scope, sign, encrypt, &sealed_size);
        if (!sealed || !scdn_sync_write_file(dir, "desired.bundle", sealed, sealed_size)) goto next;
        peer_key->verified_sequence = 0; /* Verify the persisted object once before caching it. */
        status_write(dir, "published", "", sequence, NULL, 0);
        status_write(root, "published", "", sequence, NULL, 0);
next:
        OPENSSL_free(der); der = NULL;
        EVP_PKEY_free(encrypt); encrypt = NULL; free(old); old = NULL; free(sealed); sealed = NULL;
        close(lock); lock = -1; close(dir); dir = -1;
    }
finish:
    EVP_PKEY_free(sign); EVP_PKEY_free(encrypt); OPENSSL_free(der);
    free(old); free(sealed);
    if (lock >= 0) close(lock);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
}

static void distribution_cycle(void *data, ngx_log_t *log)
{
    ngx_http_scdn_main_conf_t *main = data; (void) log;
    if (main->role == SCDN_SYNC_MASTER) master_cycle(main); else node_cycle(main);
}
static void cycle_complete(ngx_event_t *event)
{
    (void) event;
    if (!ngx_quit && !ngx_terminate && !ngx_exiting) ngx_add_timer(&dist_timer, 1000);
}
static void cycle_start(ngx_event_t *event)
{
    dist_conf *conf = dist_main->distribution;
    (void) event;
    if (ngx_quit || ngx_terminate || ngx_exiting) return;
    if (ngx_thread_task_post(conf->poll_threads, dist_task) != NGX_OK) ngx_add_timer(&dist_timer, 1000);
}
ngx_int_t scdn_sync_distribution_process(ngx_cycle_t *cycle)
{
    if ((ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) || ngx_worker != 0) return NGX_OK;
    dist_main = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_scdn_sync_module);
    if (!dist_main || !dist_main->distribution) return NGX_OK;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return NGX_ERROR;
    dist_task = ngx_thread_task_alloc(cycle->pool, 0); if (!dist_task) return NGX_ERROR;
    dist_task->ctx = dist_main; dist_task->handler = distribution_cycle;
    dist_task->event.handler = cycle_complete; dist_task->event.log = cycle->log;
    memset(&dist_timer, 0, sizeof(dist_timer)); dist_timer.handler = cycle_start; dist_timer.log = cycle->log;
    ngx_add_timer(&dist_timer, 1000); return NGX_OK;
}

static ngx_str_t *header(ngx_http_request_t *r, const char *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_str_t *found = NULL;
    ngx_uint_t i;
    size_t n = strlen(name);
    for (i = 0; ; i++) {
        if (i >= part->nelts) { if (!part->next) break; part = part->next; h = part->elts; i = 0; }
        if (h[i].hash && h[i].key.len == n && !ngx_strncasecmp(h[i].key.data, (u_char *) name, n)) {
            if (found) return NULL;
            found = &h[i].value;
        }
    }
    return found;
}
static void api_job(void *data, ngx_log_t *log)
{
    dist_job *job = data;
    dist_conf *conf = job->main->distribution;
    int root = -1, dir = -1, fd;
    u_char *desired = NULL;
    u_char metadata[SYNC_BUNDLE_HEADER];
    char hash_text[65], tag[96];
    size_t length;
    (void) log;
    job->status = 503;
    root = directory_open((char *) conf->directory.data); if (root < 0) return;
    dir = job->node.len && job->main->role == SCDN_SYNC_MASTER ? child_directory(root, &job->node) : dup(root);
    if (dir < 0) goto finish;
    if (job->operation == 1) {
        if (job->conditional[0]) {
            fd = openat(dir, "desired.bundle", O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
            if (fd >= 0) {
                if (read(fd, metadata, sizeof(metadata)) == sizeof(metadata) && !memcmp(metadata, "SCNBND02", 8)) {
                    hex(metadata + 248, hash_text);
                    snprintf(tag, sizeof(tag), "\"%llu-%s\"", (unsigned long long) scdn_sync_u64(metadata + 8), hash_text);
                    if (!strcmp(tag, job->conditional)) job->status = 304;
                }
                close(fd);
                if (job->status == 304) goto finish;
            }
        }
        job->body = read_at(dir, "desired.bundle", DIST_LIMIT, &job->length);
        job->status = job->body ? 200 : errno == ENOENT ? 204 : 503;
    } else if (job->operation == 2) {
        desired = read_at(dir, "desired.bundle", DIST_LIMIT, &length);
        if (!desired || length < SYNC_BUNDLE_HEADER) goto finish;
        if (scdn_sync_u64(desired + 8) != job->sequence || memcmp(desired + 248, job->digest, 32)) {
            job->status = 409; goto finish;
        }
        if (!status_write(dir, job->result, job->error, job->sequence,
                          !strcmp(job->result, "applied") ? job->applied : NULL, 0)) goto finish;
        job->body = read_at(dir, "status.json", 4096, &job->length); job->status = job->body ? 200 : 503;
    } else {
        job->body = read_at(dir, "status.json", 4096, &job->length);
        if (!job->body && errno == ENOENT) {
            status_write(dir, "initializing", "", 0, NULL, 0);
            job->body = read_at(dir, "status.json", 4096, &job->length);
        }
        job->status = job->body ? 200 : 503;
    }
finish:
    free(desired); if (dir >= 0) close(dir); close(root);
}
static void api_complete(ngx_event_t *event)
{
    dist_job *job = event->data;
    ngx_http_request_t *r = job->request;
    ngx_connection_t *connection = r->connection;
    ngx_str_t body;
    ngx_int_t rc;
    r->main->blocked--; r->aio = 0;
    if (r->main->terminated) { free(job->body); connection->write->handler(connection->write); return; }
    body.data = ngx_pnalloc(r->pool, job->length + 512); body.len = job->length;
    if (body.data && job->body) memcpy(body.data, job->body, job->length);
    if (body.data && job->operation != 1 && job->status == 200 && body.len >= 2
        && body.data[body.len - 2] == '}')
    {
        body.len = ngx_snprintf(body.data + body.len - 2, 512,
            ",\"role\":\"%s\",\"instance_id\":\"%V\",\"scope_id\":\"%V\","
            "\"configured_peers\":%ui,\"worker_pid\":%P}\n",
            scdn_sync_role_name(job->main->role), &job->main->id, &job->main->scope,
            job->main->peers.nelts, ngx_pid) - body.data;
    }
    free(job->body);
    if (job->operation == 1) { ngx_str_set(&r->headers_out.content_type, "application/octet-stream"); }
    if (!body.data) rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    else if (job->status == 200 || job->status == 204 || job->status == 304) rc = ngx_http_scdn_reply(r, job->status, &body);
    else rc = ngx_http_scdn_error(r, job->status, job->status == 409 ? "configuration_result_conflict" : "configuration_state_unavailable");
    ngx_http_finalize_request(r, rc); ngx_http_run_posted_requests(connection);
}
ngx_int_t scdn_sync_distribution_handler(ngx_http_request_t *r,
    ngx_http_scdn_main_conf_t *main, ngx_http_scdn_peer_t *peer, ngx_flag_t exchange)
{
    dist_conf *conf = main->distribution;
    dist_job *job;
    ngx_thread_task_t *task;
    ngx_str_t *value;
    ngx_uint_t i, operation = 0;
    ngx_http_scdn_peer_t *peers;
    uint64_t n = 0;
    if (!conf) return NGX_DECLINED;
    if (exchange && equal(&r->uri, "/_scdn_sync/v1/config/desired")) operation = 1;
    if (exchange && equal(&r->uri, "/_scdn_sync/v1/config/result")) operation = 2;
    if (!exchange && (equal(&r->uri, "/__scdn_sync/v1/config/status") || equal(&r->uri, "/__scdn_sync/v1/status"))) operation = 3;
    if (!operation) return NGX_DECLINED;
    if ((operation == 2 && r->method != NGX_HTTP_POST)
        || (operation != 2 && !(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))) return ngx_http_scdn_error(r, 405, "method_not_allowed");
    if (r != r->main || r->headers_in.chunked || r->headers_in.content_length_n > 0) return ngx_http_scdn_error(r, 400, "body_not_allowed");
    task = ngx_thread_task_alloc(r->pool, sizeof(*job)); if (!task) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    job = task->ctx; memset(job, 0, sizeof(*job)); job->main = main; job->request = r; job->operation = operation;
    if (peer) { job->node = peer->id; job->scope = peer->scope; }
    else if ((value = header(r, "X-Node-ID")) != NULL) {
        peers = main->peers.elts;
        for (i = 0; i < main->peers.nelts; i++) if (peers[i].id.len == value->len && !memcmp(peers[i].id.data, value->data, value->len)) break;
        if (i == main->peers.nelts) return ngx_http_scdn_error(r, 404, "node_not_registered");
        job->node = peers[i].id;
    }
    if (operation == 1 && (value = header(r, "If-None-Match")) != NULL) {
        if (value->len >= sizeof(job->conditional)) goto invalid;
        memcpy(job->conditional, value->data, value->len);
    }
    if (operation == 2) {
        value = header(r, "X-Config-Sequence"); if (!value || !value->len || value->len > 20) goto invalid;
        for (i = 0; i < value->len; i++) {
            if (value->data[i] < '0' || value->data[i] > '9' || n > (UINT64_MAX - 9) / 10) goto invalid;
            n = n * 10 + value->data[i] - '0';
        }
        if (!n) goto invalid;
        job->sequence = n;
        value = header(r, "X-Config-Digest");
        if (!value || !scdn_sync_decode_fingerprint(value->data, value->len, job->digest)) goto invalid;
        value = header(r, "X-Config-State");
        if (!value || (!equal(value, "applied") && !equal(value, "failed"))) goto invalid;
        memcpy(job->result, value->data, value->len);
        value = header(r, "X-Config-Error");
        if (!value || value->len >= sizeof(job->error) || !scdn_sync_valid_id(value->data, value->len)) goto invalid;
        memcpy(job->error, value->data, value->len);
        if (!strcmp(job->result, "applied")) {
            value = header(r, "X-Config-Applied");
            if (!value || !scdn_sync_decode_fingerprint(value->data, value->len, job->applied)) goto invalid;
        }
    }
    task->handler = api_job; task->event.handler = api_complete; task->event.data = job; task->event.log = r->connection->log;
    r->main->count++; r->main->blocked++; r->aio = 1;
    if (ngx_thread_task_post(conf->threads, task) != NGX_OK) {
        r->main->count--; r->main->blocked--; r->aio = 0; return ngx_http_scdn_error(r, 503, "configuration_queue_full");
    }
    return NGX_DONE;
invalid:
    return ngx_http_scdn_error(r, 400, "invalid_configuration_result");
}

static int url_valid(const ngx_str_t *value, int base, int https)
{
    CURLU *url = curl_url(); char *part = NULL; int ok = 0;
    if (!url || value->len > 2048 || curl_url_set(url, CURLUPART_URL, (char *) value->data, 0)) goto finish;
    if (curl_url_get(url, CURLUPART_SCHEME, &part, 0) || (strcmp(part, "https") && (https || strcmp(part, "http")))) goto finish;
    curl_free(part); part = NULL;
    if (!curl_url_get(url, CURLUPART_USER, &part, 0) || !curl_url_get(url, CURLUPART_PASSWORD, &part, 0)
        || !curl_url_get(url, CURLUPART_FRAGMENT, &part, 0)) goto finish;
    if (base && (!curl_url_get(url, CURLUPART_QUERY, &part, 0)
        || curl_url_get(url, CURLUPART_PATH, &part, 0) || strcmp(part, "/"))) goto finish;
    ok = 1;
finish:
    curl_free(part); curl_url_cleanup(url); return ok;
}
char *scdn_sync_distribution_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_http_scdn_main_conf_t *main = configuration;
    dist_conf *conf = main->distribution;
    ngx_str_t *v = cf->args->elts, *slot = NULL;
    dist_source *source, *sources;
    dist_peer_key *key, *keys;
    dist_probe *probe;
    ngx_uint_t i;
    if (!conf) {
        conf = ngx_pcalloc(cf->pool, sizeof(*conf)); if (!conf) return NGX_CONF_ERROR;
        conf->apply_timeout = 15000;
        main->distribution = conf;
        if (ngx_array_init(&conf->sources, cf->pool, 4, sizeof(dist_source)) != NGX_OK
            || ngx_array_init(&conf->keys, cf->pool, 4, sizeof(dist_peer_key)) != NGX_OK
            || ngx_array_init(&conf->probes, cf->pool, 4, sizeof(dist_probe)) != NGX_OK) return NGX_CONF_ERROR;
    }
    if (equal(&cmd->name, "scdn_sync_config_apply_timeout")) {
        ngx_int_t timeout = ngx_parse_time(&v[1], 0);
        if (timeout < 1000 || timeout > 600000) return "requires 1s to 10m";
        conf->apply_timeout = (ngx_msec_t) timeout; return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_source")) {
        if (!scdn_sync_valid_id(v[1].data, v[1].len) || v[2].data[0] != '/' || conf->sources.nelts >= 256) return "requires scope and absolute source path";
        sources = conf->sources.elts;
        for (i = 0; i < conf->sources.nelts; i++) if (equal(&sources[i].id, (char *) v[1].data)) return "duplicates scope";
        source = ngx_array_push(&conf->sources); if (!source) return NGX_CONF_ERROR;
        memset(source, 0, sizeof(*source)); source->id = v[1]; source->path = v[2]; return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_peer_key")) {
        if (!scdn_sync_valid_id(v[1].data, v[1].len) || v[2].data[0] != '/' || conf->keys.nelts >= 1024) return "requires node and absolute RSA public key";
        keys = conf->keys.elts;
        for (i = 0; i < conf->keys.nelts; i++) if (equal(&keys[i].id, (char *) v[1].data)) return "duplicates peer key";
        key = ngx_array_push(&conf->keys); if (!key) return NGX_CONF_ERROR;
        memset(key, 0, sizeof(*key)); key->id = v[1]; key->path = v[2]; return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_probe")) {
        ngx_int_t status = ngx_atoi(v[2].data, v[2].len);
        if (conf->probes.nelts >= 32 || !url_valid(&v[1], 0, 0) || status < 200 || status > 499) return "requires a probe URL and expected HTTP status";
        probe = ngx_array_push(&conf->probes); if (!probe) return NGX_CONF_ERROR;
        probe->url = v[1]; probe->status = status; return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_allow_empty")) {
        if (!equal(&v[1], "on") && !equal(&v[1], "off")) return "must be on or off";
        conf->allow_empty = equal(&v[1], "on"); return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_mtls")) {
        if (conf->ca.len || v[1].data[0] != '/' || v[2].data[0] != '/' || v[3].data[0] != '/') return "requires three absolute mTLS paths once";
        conf->ca = v[1]; conf->certificate = v[2]; conf->key = v[3]; return NGX_CONF_OK;
    }
    if (equal(&cmd->name, "scdn_sync_config_state")) slot = &conf->directory;
    if (equal(&cmd->name, "scdn_sync_config_signing_key")) slot = &conf->signing;
    if (equal(&cmd->name, "scdn_sync_config_trust_key")) slot = &conf->trust;
    if (equal(&cmd->name, "scdn_sync_config_decryption_key")) slot = &conf->decrypt;
    if (equal(&cmd->name, "scdn_sync_config_status_socket")) slot = &conf->status_socket;
    if (equal(&cmd->name, "scdn_sync_config_master")) {
        if (!url_valid(&v[1], 1, 1)) return "requires a root HTTPS Master URL";
        if (v[1].data[v[1].len - 1] == '/') v[1].data[--v[1].len] = 0;
        slot = &conf->master;
    }
    if (!slot || slot->len || (!equal(&cmd->name, "scdn_sync_config_master") && v[1].data[0] != '/')
        || v[1].len > 1024) return "requires one bounded absolute value";
    *slot = v[1]; return NGX_CONF_OK;
}
ngx_int_t scdn_sync_distribution_configure(ngx_conf_t *cf, ngx_http_scdn_main_conf_t *main)
{
    dist_conf *conf = main->distribution;
    ngx_str_t threads = ngx_string("scdn_sync_distribution"), polling = ngx_string("scdn_sync_publisher");
    ngx_uint_t i, j;
    ngx_http_scdn_peer_t *peers = main->peers.elts;
    dist_source *sources;
    dist_peer_key *keys;
    if (!conf) return NGX_OK;
    if (!conf->directory.len || main->role == SCDN_SYNC_OFF) goto invalid;
    if (main->role == SCDN_SYNC_MASTER) {
        if (!conf->signing.len || !conf->sources.nelts || conf->master.len || conf->decrypt.len || conf->trust.len || conf->status_socket.len) goto invalid;
        sources = conf->sources.elts; keys = conf->keys.elts;
        for (i = 0; i < main->peers.nelts; i++) {
            for (j = 0; j < conf->sources.nelts; j++) if (sources[j].id.len == peers[i].scope.len && !memcmp(sources[j].id.data, peers[i].scope.data, peers[i].scope.len)) break;
            if (j == conf->sources.nelts) goto invalid;
            for (j = 0; j < conf->keys.nelts; j++) if (keys[j].id.len == peers[i].id.len && !memcmp(keys[j].id.data, peers[i].id.data, peers[i].id.len)) break;
            if (j == conf->keys.nelts) goto invalid;
        }
    } else if (!conf->master.len || !conf->ca.len || !conf->trust.len || !conf->decrypt.len || !conf->status_socket.len
        || conf->sources.nelts || conf->keys.nelts || conf->signing.len) goto invalid;
    conf->threads = ngx_thread_pool_add(cf, &threads); conf->poll_threads = ngx_thread_pool_add(cf, &polling);
    return conf->threads && conf->poll_threads ? NGX_OK : NGX_ERROR;
invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_sync requires complete role-specific configuration distribution settings");
    return NGX_ERROR;
}
