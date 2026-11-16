/* Durable cache jobs. All disk/network operations run in a bounded thread pool. */
#include "scdn_sync_module.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/file.h>
#include <time.h>

#if !(NGX_THREADS)
#error "native-sync cache tasks require --with-threads"
#endif

#define TASK_BODY 65536
#define TASK_ITEMS 256
#define TASK_CAPACITY 128
#define TASK_LEASE 120
#define TASK_ATTEMPTS 3
#define TASK_SECONDS 45
#define TASK_DOWNLOAD (64 * 1024 * 1024)
#define TASK_FILE (TASK_BODY + 4096)

enum { TASK_QUEUED, TASK_RUNNING, TASK_SUCCEEDED, TASK_FAILED };
enum { TASK_SUBMIT = 1, TASK_STATUS, TASK_DELETE, TASK_NEXT, TASK_RESULT };

typedef struct {
    char id[97], node[97], node_scope[97], type[16], mode[16], scope[257];
    unsigned state, attempt, completed, length;
    int64_t created, lease;
    char error[40], digest[65];
    unsigned char body[TASK_BODY];
} cache_task_t;

typedef struct {
    ngx_http_scdn_main_conf_t *conf;
    ngx_http_request_t *request;
    cache_task_t task;
    unsigned operation, status;
    const char *error;
} cache_job_t;

typedef struct {
    unsigned char *body;
    size_t length, limit, transferred;
    cache_task_t *task;
    unsigned headers, invalid, cache_hit;
} cache_response_t;

static ngx_event_t cache_timer;
static ngx_thread_task_t *cache_poll_task;
static ngx_http_scdn_main_conf_t *cache_main;

static int same(const ngx_str_t *value, const char *text)
{
    return value->len == strlen(text)
        && memcmp(value->data, text, value->len) == 0;
}

static int copy_value(char *to, size_t size, const ngx_str_t *from)
{
    if (from == NULL || from->len >= size) return 0;
    memcpy(to, from->data, from->len); to[from->len] = 0; return 1;
}

static int printable(const char *value, size_t limit)
{
    size_t i, length = strlen(value);
    if (length == 0 || length > limit) return 0;
    for (i = 0; i < length; i++) {
        if ((unsigned char) value[i] < 33 || (unsigned char) value[i] > 126)
            return 0;
    }
    return 1;
}

static int identifier(const char *value)
{
    return scdn_sync_valid_id((const unsigned char *) value, strlen(value));
}

static ngx_str_t *task_header(ngx_http_request_t *r, const char *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *headers = part->elts;
    ngx_str_t *found = NULL;
    ngx_uint_t i;
    size_t length = strlen(name);
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; headers = part->elts; i = 0;
        }
        if (headers[i].hash && headers[i].key.len == length
            && ngx_strncasecmp(headers[i].key.data, (u_char *) name, length) == 0)
        {
            if (found != NULL) return NULL;
            found = &headers[i].value;
        }
    }
    return found;
}

static void sha_hex(const void *bytes, size_t length, char output[65])
{
    unsigned char digest[32];
    unsigned int size = 0, i;
    static const char hex[] = "0123456789abcdef";
    if (EVP_Digest(bytes, length, digest, &size, EVP_sha256(), NULL) != 1
        || size != 32)
    {
        output[0] = 0; return;
    }
    for (i = 0; i < 32; i++) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = 0;
}

static int task_digest(cache_task_t *task, char result[65])
{
    unsigned char *bytes;
    int n;
    bytes = malloc(TASK_FILE);
    if (bytes == NULL) return 0;
    n = snprintf((char *) bytes, TASK_FILE, "%s\n%s\n%s\n%s\n%s\n%s\n",
        task->id, task->node, task->node_scope, task->type, task->mode, task->scope);
    if (n < 0 || (size_t) n + task->length > TASK_FILE) {
        free(bytes); return 0;
    }
    memcpy(bytes + n, task->body, task->length);
    sha_hex(bytes, (size_t) n + task->length, result); free(bytes);
    return result[0] != 0;
}

static int uri_valid(const unsigned char *p, size_t n)
{
    size_t i;
    unsigned a, b;
    if (n == 0 || n > 4096 || p[0] != '/' || (n > 1 && p[1] == '/'))
        return 0;
    for (i = 0; i < n; i++) {
        if (p[i] < 33 || p[i] > 126 || p[i] == '#' || p[i] == '\\') return 0;
        if (p[i] == '%') {
            if (i + 2 >= n) return 0;
            a = p[i + 1]; b = p[i + 2];
            a = a >= '0' && a <= '9' ? a - '0'
                : a >= 'a' && a <= 'f' ? a - 'a' + 10
                : a >= 'A' && a <= 'F' ? a - 'A' + 10 : 256;
            b = b >= '0' && b <= '9' ? b - '0'
                : b >= 'a' && b <= 'f' ? b - 'a' + 10
                : b >= 'A' && b <= 'F' ? b - 'A' + 10 : 256;
            if (a > 15 || b > 15 || a * 16 + b < 32 || a * 16 + b == 127
                || a * 16 + b == '\\') return 0;
            i += 2;
        }
    }
    /* Do not let an encoded/normalized path reach a control location. */
    if (n >= 13 && (memcmp(p, "/__scdn_sync/", 13) == 0
                   || memcmp(p, "/_scdn_sync/", 12) == 0)) return 0;
    return 1;
}

static int task_valid(cache_task_t *task)
{
    size_t i, start;
    unsigned count = 0;
    int preheat = strcmp(task->type, "preheat") == 0;
    if (!identifier(task->id) || !identifier(task->node)
        || !identifier(task->node_scope) || task->length > TASK_BODY
        || (!preheat && strcmp(task->type, "refresh") != 0)
        || task->state > TASK_FAILED || task->attempt > TASK_ATTEMPTS
        || task->completed > TASK_ITEMS) return 0;
    if (preheat) {
        if (strcmp(task->mode, "exact") != 0) return 0;
    } else if (strcmp(task->mode, "exact") && strcmp(task->mode, "prefix")
        && strcmp(task->mode, "wildcard") && strcmp(task->mode, "regex")
        && strcmp(task->mode, "suffix") && strcmp(task->mode, "directory")
        && strcmp(task->mode, "scope") && strcmp(task->mode, "site")
        && strcmp(task->mode, "all") && strcmp(task->mode, "node")) return 0;
    if (!strcmp(task->mode, "all") || !strcmp(task->mode, "node")) {
        return !preheat && task->scope[0] == 0 && task->length == 0;
    }
    if (!printable(task->scope, 256)) return 0;
    if (!strcmp(task->mode, "site") || !strcmp(task->mode, "scope"))
        return task->length == 0;
    if (task->length == 0) return 0;
    for (i = 0; i < task->length; ) {
        start = i;
        while (i < task->length && task->body[i] != '\n') {
            if (task->body[i] < 32 || task->body[i] == 127) return 0;
            i++;
        }
        if (i == start || i - start > 4096 || ++count > TASK_ITEMS) return 0;
        if (preheat && !uri_valid(task->body + start, i - start)) return 0;
        if (i < task->length) i++;
    }
    return 1;
}

/* Files are private, checksummed text records; no native struct is persisted. */
static int record_save(int directory, cache_task_t *task)
{
    unsigned char *bytes;
    char checksum[65], name[112], previous[112], temporary[160];
    int fd = -1, n, result = 0;
    size_t length, done = 0;
    ssize_t wrote;
    struct timespec now;
    bytes = calloc(1, TASK_FILE);
    if (bytes == NULL) return 0;
    n = snprintf((char *) bytes + 70, TASK_FILE - 70,
        "%s\n%s\n%s\n%s\n%s\n%s\n%u\n%u\n%u\n%lld\n%lld\n%s\n%u\n%s\n",
        task->id, task->node, task->node_scope, task->type, task->mode, task->scope,
        task->state, task->attempt, task->completed, (long long) task->created,
        (long long) task->lease, task->error, task->length, task->digest);
    if (n < 0 || (size_t) n + task->length + 70 > TASK_FILE) goto finish;
    memcpy(bytes + 70 + n, task->body, task->length);
    length = (size_t) n + task->length;
    sha_hex(bytes + 70, length, checksum);
    if (checksum[0] == 0) goto finish;
    memcpy(bytes, "SCT1:", 5); memcpy(bytes + 5, checksum, 64); bytes[69] = '\n';
    length += 70;
    snprintf(name, sizeof(name), "%s.%s", task->id,
             task->state >= TASK_SUCCEEDED ? "done" : "task");
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(temporary, sizeof(temporary), ".%s.%ld.%ld.tmp", task->id,
             (long) getpid(), now.tv_nsec);
    fd = openat(directory, temporary, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) goto finish;
    while (done < length) {
        wrote = write(fd, bytes + done, length - done);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) goto finish;
        done += (size_t) wrote;
    }
    if (fsync(fd) != 0 || renameat(directory, temporary, directory, name) != 0) goto finish;
    if (task->state >= TASK_SUCCEEDED) {
        snprintf(previous, sizeof(previous), "%s.task", task->id);
        if (unlinkat(directory, previous, 0) && errno != ENOENT) goto finish;
    }
    if (fsync(directory) != 0) goto finish;
    result = 1;
finish:
    if (fd >= 0) { close(fd); unlinkat(directory, temporary, 0); }
    free(bytes); return result;
}

static int number(const char *value, uint64_t *result)
{
    uint64_t n = 0;
    const unsigned char *p = (const unsigned char *) value;
    if (*p == 0) return 0;
    while (*p) {
        if (*p < '0' || *p > '9' || n > (UINT64_MAX - 9) / 10) return 0;
        n = n * 10 + (*p++ - '0');
    }
    *result = n; return 1;
}

/* 0=absent, 1=valid, -1=corrupt/unreadable; never treat a corrupt task as done. */
static int record_load(int directory, const char *id, cache_task_t *task)
{
    unsigned char *bytes, *p, *end, *newline;
    char name[112], checksum[65], *field[14];
    struct stat st;
    size_t total = 0, i;
    ssize_t got;
    uint64_t n;
    int fd, result = -1;
    snprintf(name, sizeof(name), "%s.done", id);
    fd = openat(directory, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        snprintf(name, sizeof(name), "%s.task", id);
        fd = openat(directory, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    }
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 077)
        || st.st_nlink != 1 || st.st_uid != geteuid()
        || st.st_size < 70 || st.st_size > TASK_FILE) { close(fd); return -1; }
    bytes = malloc((size_t) st.st_size + 1);
    if (bytes == NULL) { close(fd); return -1; }
    while (total < (size_t) st.st_size) {
        got = read(fd, bytes + total, (size_t) st.st_size - total);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto finish;
        total += (size_t) got;
    }
    bytes[total] = 0;
    sha_hex(bytes + 70, total - 70, checksum);
    if (memcmp(bytes, "SCT1:", 5) || bytes[69] != '\n'
        || memcmp(bytes + 5, checksum, 64)) goto finish;
    p = bytes + 70; end = bytes + total;
    for (i = 0; i < 14; i++) {
        newline = memchr(p, '\n', (size_t) (end - p));
        if (newline == NULL || memchr(p, 0, (size_t) (newline - p)) != NULL)
            goto finish;
        *newline = 0; field[i] = (char *) p; p = newline + 1;
    }
    memset(task, 0, sizeof(*task));
#define LOAD_STRING(index, member) \
    if (strlen(field[index]) >= sizeof(task->member)) goto finish; \
    strcpy(task->member, field[index])
    LOAD_STRING(0, id); LOAD_STRING(1, node); LOAD_STRING(2, node_scope);
    LOAD_STRING(3, type); LOAD_STRING(4, mode); LOAD_STRING(5, scope);
    LOAD_STRING(11, error); LOAD_STRING(13, digest);
#undef LOAD_STRING
    for (i = 6; i <= 10; i++) {
        if (!number(field[i], &n) || n > INT64_MAX) goto finish;
        if (i <= 8 && n > UINT32_MAX) goto finish;
        if (i == 6) task->state = (unsigned) n;
        if (i == 7) task->attempt = (unsigned) n;
        if (i == 8) task->completed = (unsigned) n;
        if (i == 9) task->created = (int64_t) n;
        if (i == 10) task->lease = (int64_t) n;
    }
    if (!number(field[12], &n) || n > TASK_BODY || n != (uint64_t) (end - p))
        goto finish;
    task->length = (unsigned) n; memcpy(task->body, p, task->length);
    if (task->lease > (int64_t) time(NULL) + TASK_LEASE + 30) goto finish;
    if (strcmp(id, task->id) || !task_valid(task)
        || !task_digest(task, checksum) || strcmp(task->digest, checksum)) goto finish;
    result = 1;
finish:
    close(fd); free(bytes); return result;
}

static int private_directory(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)
        && !(st.st_mode & 077) && st.st_uid == geteuid();
}

static int task_directory(scdn_sync_tasks_conf_t *conf, const char *node)
{
    int root, fd, created;
    root = open((char *) conf->directory.data, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (root < 0) return -1;
    if (!private_directory(root)) { close(root); return -1; }
    created = mkdirat(root, node, 0700) == 0;
    if (!created && errno != EEXIST) { close(root); return -1; }
    fd = openat(root, node, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd >= 0 && (!private_directory(fd) || (created && fsync(root) != 0))) { close(fd); fd = -1; }
    close(root); return fd;
}

static int task_lock(int directory, const char *name, int nonblock)
{
    struct stat st;
    int fd = openat(directory, name, O_RDWR|O_CREAT|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077)
        || st.st_nlink != 1 || st.st_uid != geteuid()
        || flock(fd, LOCK_EX|(nonblock ? LOCK_NB : 0))) { close(fd); return -1; }
    return fd;
}

static int task_filename(const char *name, char id[97], int terminal)
{
    size_t n = strlen(name);
    if (n < 6 || n > 101 || (strcmp(name + n - 5, ".task")
        && (!terminal || strcmp(name + n - 5, ".done")))) return 0;
    memcpy(id, name, n - 5); id[n - 5] = 0; return identifier(id);
}

static unsigned task_count(int directory)
{
    DIR *dir;
    struct dirent *entry;
    char id[97];
    unsigned count = 0;
    int fd = openat(directory, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd < 0) return TASK_CAPACITY;
    dir = fdopendir(fd);
    if (dir == NULL) { close(fd); return TASK_CAPACITY; }
    while ((entry = readdir(dir)) != NULL) {
        if (task_filename(entry->d_name, id, 1)) count++;
    }
    closedir(dir); return count;
}

static void master_job(void *data, ngx_log_t *log)
{
    cache_job_t *job = data;
    cache_task_t *old;
    DIR *dir = NULL;
    struct dirent *entry;
    int directory = -1, lock = -1, fd, found;
    char id[97], filename[112];
    time_t now = time(NULL);
    (void) log;
    job->status = 503; job->error = "task_storage_unavailable";
    old = calloc(1, sizeof(*old)); if (old == NULL) return;
    directory = task_directory(&job->conf->cache, job->task.node);
    if (directory < 0 || (lock = task_lock(directory, "queue.lock", 0)) < 0) goto finish;
    if (job->operation == TASK_NEXT) {
        fd = openat(directory, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (fd < 0) goto finish;
        dir = fdopendir(fd); if (dir == NULL) { close(fd); goto finish; }
        job->status = 204; job->error = NULL;
        while ((entry = readdir(dir)) != NULL) {
            if (!task_filename(entry->d_name, id, 0)) continue;
            if (record_load(directory, id, old) != 1) {
                job->status = 503; job->error = "task_record_corrupt"; break;
            }
            if (strcmp(old->node, job->task.node)) {
                job->status = 503; job->error = "task_record_corrupt"; break;
            }
            if (strcmp(old->node_scope, job->task.node_scope)) {
                if (old->state < TASK_SUCCEEDED) {
                    old->state = TASK_FAILED; strcpy(old->error, "node_scope_changed");
                    if (!record_save(directory, old)) {
                        job->status = 503; job->error = "task_storage_unavailable"; break;
                    }
                }
                continue;
            }
            if (old->state >= TASK_SUCCEEDED
                || (old->state == TASK_RUNNING && old->lease > now)) continue;
            if (old->attempt >= TASK_ATTEMPTS) {
                old->state = TASK_FAILED; strcpy(old->error, "lease_expired");
                if (!record_save(directory, old)) {
                    job->status = 503; job->error = "task_storage_unavailable"; break;
                }
                continue;
            }
            old->state = TASK_RUNNING; old->attempt++; old->lease = now + TASK_LEASE;
            if (!record_save(directory, old)) {
                job->status = 503; job->error = "task_storage_unavailable"; break;
            }
            job->task = *old; job->status = 200; break;
        }
        goto finish;
    }
    found = record_load(directory, job->task.id, old);
    if (found < 0) { job->error = "task_record_corrupt"; goto finish; }
    if (job->operation == TASK_SUBMIT) {
        if (found) {
            if (strcmp(old->digest, job->task.digest)) {
                job->status = 409; job->error = "task_id_conflict";
            } else { job->task = *old; job->status = 200; job->error = NULL; }
            goto finish;
        }
        if (task_count(directory) >= TASK_CAPACITY) {
            job->status = 507; job->error = "task_capacity"; goto finish;
        }
        job->task.created = now;
        if (!record_save(directory, &job->task)) goto finish;
        job->status = 202; job->error = NULL; goto finish;
    }
    if (!found) { job->status = 404; job->error = "task_not_found"; goto finish; }
    if (job->operation == TASK_RESULT) {
        if (old->attempt != job->task.attempt || old->state == TASK_QUEUED
            || strcmp(old->node_scope, job->task.node_scope))
        { job->status = 409; job->error = "task_lease_conflict"; goto finish; }
        if (old->state >= TASK_SUCCEEDED) {
            if (old->state != job->task.state || old->completed != job->task.completed
                || strcmp(old->error, job->task.error))
            { job->status = 409; job->error = "task_result_conflict"; goto finish; }
        } else {
            old->state = job->task.state; old->completed = job->task.completed;
            strcpy(old->error, job->task.error);
            if (!record_save(directory, old)) goto finish;
        }
    }
    if (job->operation == TASK_DELETE) {
        if (old->state < TASK_SUCCEEDED) {
            job->status = 409; job->error = "task_not_terminal"; goto finish;
        }
        snprintf(filename, sizeof(filename), "%s.task", old->id);
        if (unlinkat(directory, filename, 0) && errno != ENOENT) goto finish;
        snprintf(filename, sizeof(filename), "%s.done", old->id);
        if (unlinkat(directory, filename, 0) || fsync(directory)) goto finish;
    }
    job->task = *old; job->status = 200; job->error = NULL;
finish:
    if (dir != NULL) closedir(dir);
    if (lock >= 0) close(lock);
    if (directory >= 0) close(directory);
    free(old);
}

static ngx_int_t job_reply(cache_job_t *job)
{
    ngx_str_t body;
    ngx_http_request_t *r = job->request;
    cache_task_t *task = &job->task;
    char lease[24];
    static const char *states[] = { "queued", "running", "succeeded", "failed" };
    if (job->error != NULL) return ngx_http_scdn_error(r, job->status, job->error);
    if (job->status == 204) {
        ngx_str_set(&body, ""); return ngx_http_scdn_reply(r, 204, &body);
    }
    if (job->operation == TASK_NEXT) {
        snprintf(lease, sizeof(lease), "%u", task->attempt);
        if (ngx_http_scdn_header(r, "X-Task-ID", task->id) != NGX_OK
            || ngx_http_scdn_header(r, "X-Node-ID", task->node) != NGX_OK
            || ngx_http_scdn_header(r, "X-Node-Scope", task->node_scope) != NGX_OK
            || ngx_http_scdn_header(r, "X-Task-Type", task->type) != NGX_OK
            || ngx_http_scdn_header(r, "X-Purge-Mode", task->mode) != NGX_OK
            || ngx_http_scdn_header(r, "X-Purge-Scope", task->scope) != NGX_OK
            || ngx_http_scdn_header(r, "X-Task-Digest", task->digest) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        /* The output header must outlive this stack frame. */
        body.len = strlen(lease); body.data = ngx_pnalloc(r->pool, body.len + 1);
        if (body.data == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        memcpy(body.data, lease, body.len + 1);
        if (ngx_http_scdn_header(r, "X-Task-Lease", (char *) body.data) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        body.data = task->body; body.len = task->length;
        ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
        return ngx_http_scdn_reply(r, 200, &body);
    }
    body.data = ngx_pnalloc(r->pool, 1024);
    if (body.data == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    body.len = ngx_snprintf(body.data, 1024,
        "{\"ok\":true,\"task_id\":\"%s\",\"node_id\":\"%s\","
        "\"type\":\"%s\",\"mode\":\"%s\",\"state\":\"%s\","
        "\"attempt\":%ud,\"completed\":%ud,\"error\":\"%s\","
        "\"physical_deleted\":false}\n", task->id, task->node, task->type,
        task->mode, states[task->state], task->attempt, task->completed, task->error)
        - body.data;
    return ngx_http_scdn_reply(r, job->status, &body);
}

static void job_complete(ngx_event_t *event)
{
    cache_job_t *job = event->data;
    ngx_http_request_t *r = job->request;
    ngx_connection_t *connection = r->connection;
    r->main->blocked--; r->aio = 0;
    if (r->main->terminated) { connection->write->handler(connection->write); return; }
    ngx_http_finalize_request(r, job_reply(job));
    ngx_http_run_posted_requests(connection);
}

static void job_body(ngx_http_request_t *r)
{
    cache_job_t *job = ngx_http_get_module_ctx(r, ngx_http_scdn_sync_module);
    ngx_chain_t *chain;
    ngx_thread_task_t *thread;
    size_t n;
    if (r->request_body != NULL && r->request_body->temp_file != NULL) goto invalid;
    for (chain = r->request_body ? r->request_body->bufs : NULL; chain; chain = chain->next) {
        if (!ngx_buf_in_memory(chain->buf) && ngx_buf_size(chain->buf)) goto invalid;
        n = (size_t) ngx_buf_size(chain->buf);
        if (n + job->task.length > TASK_BODY) goto invalid;
        if (n) memcpy(job->task.body + job->task.length, chain->buf->pos, n);
        job->task.length += (unsigned) n;
    }
    if (job->operation == TASK_SUBMIT) {
        if (!task_valid(&job->task) || !task_digest(&job->task, job->task.digest)) goto invalid;
    } else if (job->task.length) goto invalid;
    thread = ngx_thread_task_alloc(r->pool, 0);
    if (thread == NULL) goto busy;
    thread->ctx = job; thread->handler = master_job;
    thread->event.handler = job_complete; thread->event.data = job;
    thread->event.log = r->connection->log;
    r->main->blocked++; r->aio = 1;
    if (ngx_thread_task_post(job->conf->cache.threads, thread) == NGX_OK) return;
    r->main->blocked--; r->aio = 0;
busy:
    ngx_http_finalize_request(r, ngx_http_scdn_error(r, 503, "task_queue_unavailable")); return;
invalid:
    ngx_http_finalize_request(r, ngx_http_scdn_error(r, 400, "invalid_cache_task"));
}

ngx_int_t scdn_sync_tasks_handler(ngx_http_request_t *r,
    ngx_http_scdn_main_conf_t *conf, ngx_http_scdn_peer_t *peer, ngx_flag_t exchange)
{
    cache_job_t *job;
    ngx_int_t rc;
    ngx_str_t *value;
    ngx_http_scdn_peer_t *peers;
    ngx_uint_t i;
    uint64_t n;
    char number_text[32];
    unsigned operation = 0;
    if (exchange && same(&r->uri, "/_scdn_sync/v1/cache/next")) operation = TASK_NEXT;
    if (exchange && same(&r->uri, "/_scdn_sync/v1/cache/result")) operation = TASK_RESULT;
    if (!exchange && same(&r->uri, "/__scdn_sync/v1/cache/tasks")) {
        if (r->method == NGX_HTTP_POST) operation = TASK_SUBMIT;
        else if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) operation = TASK_STATUS;
        else if (r->method == NGX_HTTP_DELETE) operation = TASK_DELETE;
        else return ngx_http_scdn_error(r, 405, "method_not_allowed");
    }
    if (!operation) return NGX_DECLINED;
    if (r != r->main || !conf->cache.directory.len)
        return ngx_http_scdn_error(r, 404, "cache_tasks_disabled");
    if ((operation == TASK_NEXT || operation == TASK_RESULT) && r->method != NGX_HTTP_POST)
        return ngx_http_scdn_error(r, 405, "method_not_allowed");
    if (conf->role != SCDN_SYNC_MASTER && operation != TASK_STATUS)
        return ngx_http_scdn_error(r, 403, "master_role_required");
    if (r->headers_in.chunked || r->headers_in.content_length_n > TASK_BODY)
        return ngx_http_scdn_error(r, 413, "task_body_size");
    if (operation != TASK_SUBMIT && r->headers_in.content_length_n > 0)
        return ngx_http_scdn_error(r, 400, "request_body_not_allowed");
    job = ngx_pcalloc(r->pool, sizeof(*job));
    if (job == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    job->conf = conf; job->request = r; job->operation = operation;
    if (exchange) {
        if (peer == NULL || !copy_value(job->task.node, sizeof(job->task.node), &peer->id)
            || !copy_value(job->task.node_scope, sizeof(job->task.node_scope), &peer->scope))
            goto invalid;
        value = task_header(r, "X-Node-ID");
        if (value != NULL && !same(value, job->task.node)) goto invalid;
    } else {
        value = task_header(r, "X-Node-ID");
        if (!copy_value(job->task.node, sizeof(job->task.node), value)
            || !identifier(job->task.node)) goto invalid;
        if (conf->role == SCDN_SYNC_NODE) {
            if (!same(&conf->id, job->task.node)) goto invalid;
        } else {
            peers = conf->peers.elts;
            for (i = 0; i < conf->peers.nelts; i++) {
                if (same(&peers[i].id, job->task.node)) break;
            }
            if (i == conf->peers.nelts) return ngx_http_scdn_error(r, 404, "node_not_registered");
            if (!copy_value(job->task.node_scope, sizeof(job->task.node_scope), &peers[i].scope))
                goto invalid;
        }
    }
    if (operation != TASK_NEXT) {
        if (!copy_value(job->task.id, sizeof(job->task.id), task_header(r, "X-Task-ID"))
            || !identifier(job->task.id)) goto invalid;
    }
    if (operation == TASK_SUBMIT) {
        value = task_header(r, "Content-Type");
        if (value == NULL || !same(value, "text/plain"))
            return ngx_http_scdn_error(r, 415, "content_type");
        if (!copy_value(job->task.type, sizeof(job->task.type), task_header(r, "X-Task-Type"))
            || !copy_value(job->task.mode, sizeof(job->task.mode), task_header(r, "X-Purge-Mode")))
            goto invalid;
        value = task_header(r, "X-Purge-Scope");
        if (value != NULL && !copy_value(job->task.scope, sizeof(job->task.scope), value)) goto invalid;
        if ((!strcmp(job->task.mode, "all") || !strcmp(job->task.mode, "node"))
            && !conf->cache.allow_all) return ngx_http_scdn_error(r, 403, "all_disabled");
    }
    if (operation == TASK_RESULT) {
        value = task_header(r, "X-Task-State");
        if (value == NULL) goto invalid;
        if (same(value, "succeeded")) job->task.state = TASK_SUCCEEDED;
        else if (same(value, "failed")) job->task.state = TASK_FAILED;
        else goto invalid;
        if (!copy_value(number_text, sizeof(number_text), task_header(r, "X-Task-Lease"))
            || !number(number_text, &n) || n == 0 || n > TASK_ATTEMPTS) goto invalid;
        job->task.attempt = (unsigned) n;
        if (!copy_value(number_text, sizeof(number_text), task_header(r, "X-Task-Completed"))
            || !number(number_text, &n) || n > TASK_ITEMS) goto invalid;
        job->task.completed = (unsigned) n;
        value = task_header(r, "X-Task-Error");
        if (value != NULL && (!copy_value(job->task.error, sizeof(job->task.error), value)
            || !identifier(job->task.error))) goto invalid;
        if ((job->task.state == TASK_SUCCEEDED && job->task.error[0])
            || (job->task.state == TASK_FAILED && !job->task.error[0])) goto invalid;
    }
    ngx_http_set_ctx(r, job, ngx_http_scdn_sync_module);
    r->request_body_in_single_buf = 1;
    rc = ngx_http_read_client_request_body(r, job_body);
    return rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc : NGX_DONE;
invalid:
    return ngx_http_scdn_error(r, 400, "invalid_cache_task");
}

/* HTTP clients never inherit proxy environment, caller headers or redirects. */
static size_t receive_body(char *p, size_t size, size_t count, void *data)
{
    cache_response_t *response = data;
    size_t n = size * count;
    if (n > response->limit - response->transferred) return 0;
    response->transferred += n;
    if (response->body != NULL) {
        memcpy(response->body + response->length, p, n); response->length += n;
    }
    return n;
}

static size_t receive_header(char *p, size_t size, size_t count, void *data)
{
    cache_response_t *response = data;
    cache_task_t *task = response->task;
    size_t n = size * count, length;
    char value[512];
    const char *colon, *end;
    unsigned bit = 0;
    char *target = NULL;
    size_t capacity = 0;
    uint64_t numeric;
    colon = memchr(p, ':', n); if (colon == NULL) return n;
    end = p + n;
    while (end > colon && (end[-1] == '\r' || end[-1] == '\n' || end[-1] == ' ')) end--;
    length = (size_t) (colon - p); colon++;
    while (colon < end && *colon == ' ') colon++;
    if ((size_t) (end - colon) >= sizeof(value)) return n;
    memcpy(value, colon, (size_t) (end - colon)); value[end - colon] = 0;
    if ((length == 7 && !strncasecmp(p, "X-Cache", length))
        || (length == 14 && !strncasecmp(p, "X-Cache-Status", length)))
    { response->cache_hit = !strcmp(value, "HIT"); return n; }
    if (task == NULL) return n;
#define HEADER(name, member, mask) \
    if (length == sizeof(name) - 1 && !strncasecmp(p, name, length)) { \
        target = task->member; capacity = sizeof(task->member); bit = mask; }
    HEADER("X-Task-ID", id, 1)
    HEADER("X-Node-ID", node, 2)
    HEADER("X-Node-Scope", node_scope, 4)
    HEADER("X-Task-Type", type, 8)
    HEADER("X-Purge-Mode", mode, 16)
    HEADER("X-Purge-Scope", scope, 32)
    HEADER("X-Task-Digest", digest, 64)
#undef HEADER
    if (length == 12 && !strncasecmp(p, "X-Task-Lease", length)) {
        bit = 128;
        if (!number(value, &numeric) || numeric == 0 || numeric > TASK_ATTEMPTS)
            response->invalid = 1;
        else task->attempt = (unsigned) numeric;
    }
    if (bit) {
        if (response->headers & bit) response->invalid = 1;
        response->headers |= bit;
        if (target != NULL) {
            if (strlen(value) >= capacity) response->invalid = 1;
            else strcpy(target, value);
        }
    }
    return n;
}

static CURL *client(const char *url, cache_response_t *response, long timeout)
{
    CURL *curl = curl_easy_init();
    if (curl == NULL) return NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, receive_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
    return curl;
}

static int perform(CURL *curl, long expected)
{
    long status = 0;
    CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    return result == CURLE_OK ? (expected ? status == expected : (int) status) : 0;
}

static int remote(ngx_http_scdn_main_conf_t *conf, const char *path,
    struct curl_slist *headers, cache_response_t *response)
{
    scdn_sync_tasks_conf_t *cache = &conf->cache;
    char url[4096];
    CURL *curl;
    int result;
    snprintf(url, sizeof(url), "%s%s", cache->master.data, path);
    curl = client(url, response, 5000L); if (curl == NULL) return 0;
    curl_easy_setopt(curl, CURLOPT_CAINFO, cache->ca.data);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cache->certificate.data);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, cache->key.data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    result = perform(curl, 0); curl_easy_cleanup(curl); return result;
}

static scdn_sync_cache_site_t *site_for(scdn_sync_tasks_conf_t *cache, const char *scope)
{
    ngx_uint_t i;
    scdn_sync_cache_site_t *sites = cache->sites.elts;
    for (i = 0; i < cache->sites.nelts; i++) if (same(&sites[i].scope, scope)) return &sites[i];
    return NULL;
}

static int refresh(scdn_sync_tasks_conf_t *cache, cache_task_t *task)
{
    struct curl_slist *headers = NULL;
    CURL *curl;
    cache_response_t response;
    char header[512], authorization[180];
    unsigned i, count = 0;
    int result;
    memset(&response, 0, sizeof(response)); response.limit = 4096;
    snprintf(authorization, sizeof(authorization), "Authorization: Bearer %.*s",
             (int) cache->purge_token.len, cache->purge_token.data);
    headers = curl_slist_append(headers, authorization);
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    snprintf(header, sizeof(header), "X-Purge-Mode: %s", task->mode);
    headers = curl_slist_append(headers, header);
    snprintf(header, sizeof(header), "X-Purge-Scope: %s", task->scope);
    headers = curl_slist_append(headers, header);
    snprintf(header, sizeof(header), "http://localhost%s", cache->purge_path.data);
    curl = client(header, &response, 10000L);
    if (curl == NULL) { curl_slist_free_all(headers); return 0; }
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, cache->purge_socket.data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, task->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) task->length);
    result = perform(curl, 200); curl_easy_cleanup(curl); curl_slist_free_all(headers);
    scdn_sync_clear(authorization, sizeof(authorization));
    if (result) {
        for (i = 0; i < task->length; i++) if (task->body[i] == '\n') count++;
        if (task->length && task->body[task->length - 1] != '\n') count++;
        task->completed = count ? count : 1;
    }
    return result;
}

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int preheat(scdn_sync_tasks_conf_t *cache, cache_task_t *task,
    scdn_sync_cache_site_t *site)
{
    unsigned start, end, pass;
    char url[8192];
    CURL *curl;
    struct curl_slist *connect = NULL;
    cache_response_t response;
    int result = 1;
    int64_t remaining, deadline = milliseconds() + TASK_SECONDS * 1000;
    connect = curl_slist_append(connect, (char *) site->connect.data);
    if (connect == NULL) return 0;
    for (start = 0; start < task->length; start = end + 1) {
        for (end = start; end < task->length && task->body[end] != '\n'; end++) { }
        snprintf(url, sizeof(url), "%s%.*s", site->url.data,
                 (int) (end - start), task->body + start);
        for (pass = 0; pass < 2; pass++) {
            remaining = deadline - milliseconds();
            if (remaining <= 0) { strcpy(task->error, "task_deadline"); result = 0; goto finish; }
            memset(&response, 0, sizeof(response)); response.limit = TASK_DOWNLOAD;
            curl = client(url, &response, (long) (remaining < 5000 ? remaining : 5000));
            if (curl == NULL) { result = 0; goto finish; }
            curl_easy_setopt(curl, CURLOPT_CONNECT_TO, connect);
            curl_easy_setopt(curl, CURLOPT_PATH_AS_IS, 1L);
            if (cache->local_ca.len) curl_easy_setopt(curl, CURLOPT_CAINFO, cache->local_ca.data);
            result = perform(curl, 200); curl_easy_cleanup(curl);
            if (!result) { strcpy(task->error, "preheat_http_failed"); goto finish; }
            if (response.cache_hit) break;
        }
        if (!response.cache_hit) { strcpy(task->error, "preheat_not_cached"); result = 0; goto finish; }
        task->completed++;
    }
finish:
    curl_slist_free_all(connect); return result;
}

static int acknowledge(ngx_http_scdn_main_conf_t *conf, cache_task_t *task)
{
    char header[256];
    struct curl_slist *headers = NULL;
    cache_response_t response;
    int result;
    memset(&response, 0, sizeof(response)); response.limit = 4096;
    snprintf(header, sizeof(header), "X-Task-ID: %s", task->id);
    headers = curl_slist_append(headers, header);
    snprintf(header, sizeof(header), "X-Task-Lease: %u", task->attempt);
    headers = curl_slist_append(headers, header);
    snprintf(header, sizeof(header), "X-Task-State: %s", task->state == TASK_SUCCEEDED ? "succeeded" : "failed");
    headers = curl_slist_append(headers, header);
    snprintf(header, sizeof(header), "X-Task-Completed: %u", task->completed);
    headers = curl_slist_append(headers, header);
    if (task->error[0]) {
        snprintf(header, sizeof(header), "X-Task-Error: %s", task->error);
        headers = curl_slist_append(headers, header);
    }
    result = remote(conf, "/_scdn_sync/v1/cache/result", headers, &response) == 200;
    curl_slist_free_all(headers);
    return result;
}

/* Keep at most 128 Node receipts; only a durably acknowledged terminal receipt
 * can be pruned. An unacknowledged effect must survive retries and restarts. */
static int receipt_room(int directory)
{
    DIR *dir;
    struct dirent *entry;
    cache_task_t *task;
    char id[97], oldest[97] = "", filename[112];
    int64_t created = INT64_MAX;
    int fd;
    if (task_count(directory) < TASK_CAPACITY) return 1;
    fd = openat(directory, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd < 0) return 0;
    dir = fdopendir(fd); if (dir == NULL) { close(fd); return 0; }
    task = calloc(1, sizeof(*task));
    if (task == NULL) { closedir(dir); return 0; }
    while ((entry = readdir(dir)) != NULL) {
        if (!task_filename(entry->d_name, id, 1)) continue;
        if (record_load(directory, id, task) == 1 && task->state >= TASK_SUCCEEDED
            && task->lease == 0 && task->created < created)
        { strcpy(oldest, id); created = task->created; }
    }
    free(task); closedir(dir);
    if (!oldest[0]) return 0;
    snprintf(filename, sizeof(filename), "%s.task", oldest);
    if (unlinkat(directory, filename, 0) && errno != ENOENT) return 0;
    snprintf(filename, sizeof(filename), "%s.done", oldest);
    return unlinkat(directory, filename, 0) == 0 && fsync(directory) == 0;
}

static void node_poll(void *data, ngx_log_t *log)
{
    ngx_http_scdn_main_conf_t *conf = data;
    cache_task_t *task = NULL, *old = NULL;
    cache_response_t response;
    scdn_sync_cache_site_t *site;
    char digest[65], id[97];
    int directory = -1, lock = -1, found, result = 0, remote_status;
    const char *failure = "task_storage_unavailable";
    static time_t warned;
    if (!copy_value(id, sizeof(id), &conf->id)) return;
    directory = task_directory(&conf->cache, id);
    if (directory < 0 || (lock = task_lock(directory, "runner.lock", 1)) < 0) goto finish;
    task = calloc(1, sizeof(*task)); old = calloc(1, sizeof(*old));
    if (task == NULL || old == NULL) goto finish;
    memset(&response, 0, sizeof(response)); response.body = task->body;
    response.limit = TASK_BODY; response.task = task;
    remote_status = remote(conf, "/_scdn_sync/v1/cache/next", NULL, &response);
    failure = remote_status == 204 ? NULL : "master_exchange_failed";
    if (remote_status != 200) goto finish;
    task->length = (unsigned) response.length;
    failure = "task_payload_invalid";
    if (response.invalid || response.headers != 255 || !task_valid(task)
        || !same(&conf->id, task->node) || !same(&conf->scope, task->node_scope)
        || !task_digest(task, digest) || strcmp(digest, task->digest)) goto finish;
    failure = "task_storage_unavailable";
    found = record_load(directory, task->id, old);
    if (found < 0) goto finish;
    if (found && strcmp(old->digest, task->digest)) goto finish;
    if (found && old->state >= TASK_SUCCEEDED) {
        old->attempt = task->attempt;
        failure = "task_ack_failed";
        if (acknowledge(conf, old)) {
            old->lease = 0;
            if (record_save(directory, old)) failure = NULL;
        }
        goto finish;
    }
    if (!found && !receipt_room(directory)) goto finish;
    task->state = TASK_RUNNING; task->created = time(NULL);
    /* The wire lease field is the attempt number, not an expiry timestamp.
     * A nonzero durable marker protects the receipt until Master accepts it. */
    task->lease = task->created + TASK_LEASE;
    if (!record_save(directory, task)) goto finish;
    site = site_for(&conf->cache, task->scope);
    if (!strcmp(task->mode, "all") || !strcmp(task->mode, "node")) {
        if (!conf->cache.allow_all) strcpy(task->error, "all_disabled");
        else result = refresh(&conf->cache, task);
    } else if (site == NULL) strcpy(task->error, "scope_not_allowed");
    else if (!strcmp(task->type, "refresh")) result = refresh(&conf->cache, task);
    else result = preheat(&conf->cache, task, site);
    task->state = result ? TASK_SUCCEEDED : TASK_FAILED;
    if (!result && !task->error[0]) strcpy(task->error, "cache_execution_failed");
    if (record_save(directory, task)) {
        failure = "task_ack_failed";
        if (acknowledge(conf, task)) {
            task->lease = 0;
            if (record_save(directory, task)) failure = NULL;
        }
    }
finish:
    if (failure != NULL && time(NULL) - warned >= 60) {
        warned = time(NULL);
        ngx_log_error(NGX_LOG_WARN, log, 0, "scdn_sync cache task: %s", failure);
    }
    free(task); free(old);
    if (lock >= 0) close(lock);
    if (directory >= 0) close(directory);
}

static void poll_complete(ngx_event_t *event)
{
    (void) event;
    if (!ngx_exiting && !ngx_quit && !ngx_terminate)
        ngx_add_timer(&cache_timer, cache_main->cache.poll);
}

static void poll_start(ngx_event_t *event)
{
    (void) event;
    if (ngx_exiting || ngx_quit || ngx_terminate) return;
    if (ngx_thread_task_post(cache_main->cache.threads, cache_poll_task) != NGX_OK)
        ngx_add_timer(&cache_timer, cache_main->cache.poll);
}

ngx_int_t scdn_sync_tasks_process(ngx_cycle_t *cycle)
{
    ngx_http_scdn_main_conf_t *conf;
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) return NGX_OK;
    conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_scdn_sync_module);
    if (conf == NULL || !conf->cache.directory.len) return NGX_OK;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return NGX_ERROR;
    if (conf->role != SCDN_SYNC_NODE || ngx_worker != 0) return NGX_OK;
    cache_main = conf;
    cache_poll_task = ngx_thread_task_alloc(cycle->pool, 0);
    if (cache_poll_task == NULL) return NGX_ERROR;
    cache_poll_task->ctx = conf; cache_poll_task->handler = node_poll;
    cache_poll_task->event.handler = poll_complete;
    cache_poll_task->event.log = cycle->log;
    memset(&cache_timer, 0, sizeof(cache_timer));
    cache_timer.handler = poll_start; cache_timer.log = cycle->log;
    ngx_add_timer(&cache_timer, conf->cache.poll); return NGX_OK;
}

/* Only a base URL is accepted. Preheat always connects to local IPv4 loopback. */
static int base_url(ngx_conf_t *cf, ngx_str_t *value, ngx_str_t *connect, int tls)
{
    CURLU *url;
    char *scheme = NULL, *host = NULL, *port = NULL, *part = NULL;
    int valid = 0;
    size_t size;
    url = curl_url(); if (url == NULL) return 0;
    if (value->len > 2048 || curl_url_set(url, CURLUPART_URL, (char *) value->data, 0)) goto finish;
    if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0)
        || (strcmp(scheme, "https") && (tls || strcmp(scheme, "http")))
        || curl_url_get(url, CURLUPART_HOST, &host, 0)
        || curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT)) goto finish;
    if (!curl_url_get(url, CURLUPART_USER, &part, 0)) goto finish;
    if (!curl_url_get(url, CURLUPART_PASSWORD, &part, 0)) goto finish;
    if (!curl_url_get(url, CURLUPART_QUERY, &part, 0)) goto finish;
    if (!curl_url_get(url, CURLUPART_FRAGMENT, &part, 0)) goto finish;
    if (curl_url_get(url, CURLUPART_PATH, &part, 0) || strcmp(part, "/")) goto finish;
    if (connect != NULL) {
        size = strlen(host) + strlen(port) * 2 + 32;
        connect->data = ngx_pnalloc(cf->pool, size);
        if (connect->data == NULL) goto finish;
        connect->len = (size_t) snprintf((char *) connect->data, size,
            "%s:%s:127.0.0.1:%s", host, port, port);
    }
    if (value->len && value->data[value->len - 1] == '/') value->data[--value->len] = 0;
    valid = 1;
finish:
    curl_free(scheme); curl_free(host); curl_free(port); curl_free(part);
    curl_url_cleanup(url); return valid;
}

char *scdn_sync_tasks_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_http_scdn_main_conf_t *conf = configuration;
    scdn_sync_tasks_conf_t *cache = &conf->cache;
    ngx_str_t *v = cf->args->elts;
    scdn_sync_cache_site_t *site, *sites;
    ngx_uint_t i, bit = 0;
    time_t interval;
    if (same(&cmd->name, "scdn_sync_cache_site")) {
        if (!cache->sites.elts && ngx_array_init(&cache->sites, cf->pool, 4,
                sizeof(scdn_sync_cache_site_t)) != NGX_OK) return NGX_CONF_ERROR;
        if (v[1].len == 0 || v[1].len > 256) return "requires a bounded cache scope";
        for (i = 0; i < v[1].len; i++) if (v[1].data[i] < 33 || v[1].data[i] > 126)
            return "requires a printable cache scope";
        sites = cache->sites.elts;
        for (i = 0; i < cache->sites.nelts; i++) if (same(&sites[i].scope, (char *) v[1].data))
            return "duplicates a cache scope";
        if (cache->sites.nelts >= 256) return "exceeds the cache scope limit";
        site = ngx_array_push(&cache->sites); if (site == NULL) return NGX_CONF_ERROR;
        site->scope = v[1]; site->url = v[2];
        if (!base_url(cf, &site->url, &site->connect, 0)) return "requires an HTTP(S) site base URL";
        cache->configured |= 256; return NGX_CONF_OK;
    }
    if (same(&cmd->name, "scdn_sync_cache_tasks")) bit = 1;
    if (same(&cmd->name, "scdn_sync_cache_master")) bit = 2;
    if (same(&cmd->name, "scdn_sync_cache_mtls")) bit = 4;
    if (same(&cmd->name, "scdn_sync_cache_purge")) bit = 8;
    if (same(&cmd->name, "scdn_sync_cache_local_ca")) bit = 16;
    if (same(&cmd->name, "scdn_sync_cache_poll")) bit = 32;
    if (same(&cmd->name, "scdn_sync_cache_allow_all")) bit = 64;
    if (!bit || (cache->configured & bit)) return "is duplicate";
    cache->configured |= bit;
    switch (bit) {
    case 1: cache->directory = v[1]; break;
    case 2:
        cache->master = v[1];
        if (!base_url(cf, &cache->master, NULL, 1)) return "requires an HTTPS Master base URL";
        break;
    case 4: cache->ca = v[1]; cache->certificate = v[2]; cache->key = v[3]; break;
    case 8: cache->purge_socket = v[1]; cache->purge_token_file = v[2]; cache->purge_path = v[3]; break;
    case 16: cache->local_ca = v[1]; break;
    case 32:
        interval = ngx_parse_time(&v[1], 0);
        if (interval < 100 || interval > 60000) return "must be between 100ms and 60s";
        cache->poll = (ngx_msec_t) interval; break;
    case 64:
        if (same(&v[1], "on")) cache->allow_all = 1;
        else if (!same(&v[1], "off")) return "must be on or off";
        break;
    }
    return NGX_CONF_OK;
}

ngx_int_t scdn_sync_tasks_configure(ngx_conf_t *cf, ngx_http_scdn_main_conf_t *conf)
{
    scdn_sync_tasks_conf_t *cache = &conf->cache;
    ngx_str_t pool = ngx_string("scdn_sync_tasks");
    ngx_str_t *paths[] = { &cache->directory, &cache->ca, &cache->certificate,
        &cache->key, &cache->purge_socket, &cache->purge_token_file, &cache->local_ca };
    size_t i;
    if (!cache->configured) return NGX_OK;
    if (conf->role == SCDN_SYNC_OFF || !cache->directory.len) goto invalid;
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (paths[i]->len && paths[i]->data[0] != '/') goto invalid;
    }
    if (conf->role == SCDN_SYNC_MASTER) {
        if (cache->configured & ~(1|64)) goto invalid;
    } else {
        if (!cache->master.len || !cache->ca.len || !cache->certificate.len || !cache->key.len
            || !cache->purge_socket.len || !cache->purge_path.len || cache->purge_path.data[0] != '/'
            || !cache->sites.nelts) goto invalid;
        for (i = 0; i < cache->purge_path.len; i++) {
            if (cache->purge_path.data[i] <= 32 || cache->purge_path.data[i] > 126
                || cache->purge_path.data[i] == '?' || cache->purge_path.data[i] == '#') goto invalid;
        }
        if (scdn_sync_load_token(cf, &cache->purge_token_file, &cache->purge_token) != NGX_OK)
            return NGX_ERROR;
    }
    if (!cache->poll) cache->poll = 1000;
    cache->threads = ngx_thread_pool_add(cf, &pool);
    return cache->threads == NULL ? NGX_ERROR : NGX_OK;
invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "scdn_sync cache tasks require an active role, absolute private state directory "
        "and complete Node mTLS/purge/site settings; Master accepts only tasks and allow_all");
    return NGX_ERROR;
}
