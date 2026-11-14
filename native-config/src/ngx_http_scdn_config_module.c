#include "scdn_config.h"
#include <ngx_thread_pool.h>

#if !(NGX_THREADS)
#error "scdn_config requires nginx --with-threads"
#endif

typedef struct {
    ngx_pid_t pid;
    ngx_msec_t heartbeat;
    u_char prepared[32];
} scdn_worker_slot_t;

typedef struct {
    ngx_uint_t generation, workers;
    u_char active[32];
    scdn_worker_slot_t slots[SCDN_CONFIG_WORKERS];
} scdn_shared_t;

typedef struct {
    ngx_str_t file;
    ngx_msec_t interval, settle;
    ngx_flag_t allow_empty;
    ngx_shm_zone_t *zone;
    ngx_slab_pool_t *slab;
    scdn_shared_t *shared;
    ngx_thread_pool_t *threads;
    scdn_config_snapshot_t *bootstrap;
} scdn_main_t;

typedef struct {
    ngx_flag_t status;
} scdn_location_t;

typedef struct {
    const char *path, *error;
    scdn_config_snapshot_t *result;
    scdn_config_snapshot_t *cache;
} scdn_job_t;

static scdn_main_t *scdn_main;
static scdn_config_snapshot_t *scdn_current, *scdn_prepared;
static ngx_msec_t scdn_since;
static const char *scdn_error;
static ngx_flag_t scdn_busy;
static ngx_event_t scdn_timer;
static ngx_thread_task_t *scdn_task;

static void *scdn_create_main(ngx_conf_t *cf);
static char *scdn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static char *scdn_watch(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static char *scdn_status_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data);
static void *scdn_create_location(ngx_conf_t *cf);
static char *scdn_merge_location(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t scdn_configure(ngx_conf_t *cf);
static ngx_int_t scdn_zone_init(ngx_shm_zone_t *zone, void *old);
static ngx_int_t scdn_worker_init(ngx_cycle_t *cycle);
static void scdn_worker_exit(ngx_cycle_t *cycle);
static ngx_int_t scdn_status(ngx_http_request_t *r);

static ngx_command_t scdn_commands[] = {
    { ngx_string("scdn_config_watch"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_watch, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_config_zone"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      scdn_zone, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_config_interval"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot, NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(scdn_main_t, interval), NULL },
    { ngx_string("scdn_config_settle"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot, NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(scdn_main_t, settle), NULL },
    { ngx_string("scdn_config_allow_empty"), NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(scdn_main_t, allow_empty), NULL },
    { ngx_string("scdn_config_status"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      scdn_status_directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    ngx_null_command
};

static ngx_http_module_t scdn_context = {
    NULL, scdn_configure, scdn_create_main, NULL, NULL, NULL,
    scdn_create_location, scdn_merge_location
};

ngx_module_t ngx_http_scdn_config_module = {
    NGX_MODULE_V1, &scdn_context, scdn_commands, NGX_HTTP_MODULE,
    NULL, NULL, scdn_worker_init, NULL, NULL, scdn_worker_exit, NULL,
    NGX_MODULE_V1_PADDING
};

static void *
scdn_create_main(ngx_conf_t *cf)
{
    scdn_main_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf != NULL) {
        conf->interval = NGX_CONF_UNSET_MSEC;
        conf->settle = NGX_CONF_UNSET_MSEC;
        conf->allow_empty = NGX_CONF_UNSET;
    }
    return conf;
}

static void *
scdn_create_location(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(scdn_location_t));
}

static char *
scdn_merge_location(ngx_conf_t *cf, void *parent, void *child)
{
    scdn_location_t *conf = child;
    ngx_http_core_loc_conf_t *location;
    (void) parent;
    location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (conf->status && location->handler != scdn_status) {
        return "scdn_config_status conflicts with another content handler";
    }
    return NGX_CONF_OK;
}

static char *
scdn_status_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    scdn_location_t *conf = data;
    ngx_http_core_loc_conf_t *location;
    (void) cmd;
    location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (conf->status || location->handler != NULL) {
        return "duplicates or conflicts with a content handler";
    }
    conf->status = 1;
    location->handler = scdn_status;
    return NGX_CONF_OK;
}

static char *
scdn_watch(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    scdn_main_t *conf = data;
    ngx_str_t *values = cf->args->elts;
    ngx_str_t pool_name = ngx_string("scdn_config_reader");
    (void) cmd;
    if (conf->file.data != NULL) { return "is duplicate"; }
    if (values[1].len < 2 || values[1].data[0] != '/') {
        return "requires an absolute configuration file path";
    }
    conf->file = values[1];
    conf->threads = ngx_thread_pool_add(cf, &pool_name);
    if (conf->threads == NULL) { return NGX_CONF_ERROR; }
    return NGX_CONF_OK;
}

static char *
scdn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *data)
{
    scdn_main_t *conf = data;
    ngx_str_t *values = cf->args->elts;
    ssize_t size;
    (void) cmd;
    if (conf->zone != NULL) { return "is duplicate"; }
    size = ngx_parse_size(&values[2]);
    if (size < 65536 || size > 4 * 1024 * 1024) {
        return "requires a shared zone size from 64k to 4m";
    }
    conf->zone = ngx_shared_memory_add(cf, &values[1], size,
                                      &ngx_http_scdn_config_module);
    if (conf->zone == NULL) { return NGX_CONF_ERROR; }
    conf->zone->data = conf;
    conf->zone->init = scdn_zone_init;
    /* Separate manual reload cycles; old draining workers retain their mapping. */
    conf->zone->noreuse = 1;
    return NGX_CONF_OK;
}

static void
scdn_bootstrap_cleanup(void *data)
{
    scdn_config_destroy(data);
}

static ngx_int_t
scdn_configure(ngx_conf_t *cf)
{
    scdn_main_t *conf;
    ngx_core_conf_t *core;
    ngx_pool_cleanup_t *cleanup;
    const char *error;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_config_module);
    if (conf->file.data == NULL) {
        if (conf->zone != NULL) { return NGX_ERROR; }
        return NGX_OK;
    }
    if (conf->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_config_watch requires scdn_config_zone");
        return NGX_ERROR;
    }
    ngx_conf_init_msec_value(conf->interval, 250);
    ngx_conf_init_msec_value(conf->settle, 500);
    ngx_conf_init_value(conf->allow_empty, 0);
    if (conf->interval < 50 || conf->interval > 60000
        || conf->settle < conf->interval || conf->settle > 120000)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_config invalid polling or stable interval");
        return NGX_ERROR;
    }
    core = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);
    if (core->worker_processes < 1 || core->worker_processes > SCDN_CONFIG_WORKERS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_config supports 1 to 128 workers");
        return NGX_ERROR;
    }
    conf->bootstrap = scdn_config_load((char *) conf->file.data, &error);
    if (conf->bootstrap == NULL || (!conf->allow_empty && conf->bootstrap->count == 0)) {
        if (conf->bootstrap != NULL) { scdn_config_destroy(conf->bootstrap); conf->bootstrap = NULL; error = "empty_configuration"; }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "scdn_config bootstrap rejected: %s", error);
        return NGX_ERROR;
    }
    cleanup = ngx_pool_cleanup_add(cf->pool, 0);
    if (cleanup == NULL) { scdn_config_destroy(conf->bootstrap); return NGX_ERROR; }
    cleanup->handler = scdn_bootstrap_cleanup;
    cleanup->data = conf->bootstrap;
    return NGX_OK;
}

ngx_flag_t
scdn_config_enabled(ngx_conf_t *cf)
{
    scdn_main_t *conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_config_module);
    return conf != NULL && conf->file.data != NULL && conf->zone != NULL;
}

static ngx_int_t
scdn_zone_init(ngx_shm_zone_t *zone, void *old)
{
    scdn_main_t *conf = zone->data;
    (void) old;
    conf->slab = (ngx_slab_pool_t *) zone->shm.addr;
    conf->shared = ngx_slab_calloc(conf->slab, sizeof(scdn_shared_t));
    if (conf->shared == NULL || conf->bootstrap == NULL) { return NGX_ERROR; }
    conf->shared->generation = 1;
    ngx_memcpy(conf->shared->active, conf->bootstrap->digest, 32);
    return NGX_OK;
}

void
scdn_config_release(scdn_config_snapshot_t *snapshot)
{
    if (snapshot != NULL && --snapshot->refs == 0) { scdn_config_destroy(snapshot); }
}

static void
scdn_adopt(void)
{
    u_char active[32];
    scdn_config_snapshot_t *previous;
    if (scdn_main == NULL || scdn_main->shared == NULL) { return; }
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    ngx_memcpy(active, scdn_main->shared->active, 32);
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    if (scdn_prepared != NULL && ngx_memcmp(active, scdn_prepared->digest, 32) == 0) {
        previous = scdn_current;
        scdn_current = scdn_prepared;
        scdn_prepared = NULL;
        scdn_config_release(previous);
    }
}

scdn_config_snapshot_t *
scdn_config_acquire(void)
{
    ngx_flag_t matches;
    scdn_adopt();
    if (scdn_main == NULL || scdn_main->shared == NULL) { return NULL; }
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    matches = scdn_current != NULL
              && ngx_memcmp(scdn_main->shared->active, scdn_current->digest, 32) == 0;
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    if (!matches) { return NULL; }
    if (scdn_current != NULL) { scdn_current->refs++; }
    return scdn_current;
}

static void
scdn_scan(void *data, ngx_log_t *log)
{
    scdn_job_t *job = data;
    (void) log;
    job->result = scdn_config_load_cached(job->path, &job->error, job->cache);
}

static void
scdn_complete(ngx_event_t *event)
{
    scdn_job_t *job = event->data;
    scdn_config_snapshot_t *result = job->result;
    scdn_shared_t *shared = scdn_main->shared;
    scdn_worker_slot_t *slot;
    ngx_uint_t i;
    ngx_flag_t ready = 1;

    scdn_busy = 0;
    job->result = NULL;
    scdn_config_release(job->cache);
    job->cache = NULL;
    scdn_adopt();
    if (ngx_exiting || ngx_quit || ngx_terminate) {
        scdn_config_release(result); return;
    }
    if (result != NULL && result->count == 0 && !scdn_main->allow_empty) {
        scdn_config_release(result); result = NULL; job->error = "empty_configuration";
    }
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    slot = &shared->slots[ngx_worker];
    slot->pid = ngx_pid;
    slot->heartbeat = ngx_current_msec;
    /* Withdrawing readiness under the lock prevents committing a freed candidate. */
    ngx_memcpy(slot->prepared, scdn_current->digest, 32);
    if (result != NULL) {
        scdn_error = NULL;
        if (ngx_memcmp(result->digest, scdn_current->digest, 32) == 0) {
            scdn_config_release(result);
            scdn_config_release(scdn_prepared); scdn_prepared = NULL;
        } else if (scdn_prepared == NULL
                   || ngx_memcmp(result->digest, scdn_prepared->digest, 32) != 0)
        {
            scdn_config_release(scdn_prepared);
            scdn_prepared = result;
            scdn_since = ngx_current_msec;
        } else {
            scdn_config_release(result);
            if ((ngx_msec_int_t) (ngx_current_msec - scdn_since)
                >= (ngx_msec_int_t) scdn_main->settle)
            {
                ngx_memcpy(slot->prepared, scdn_prepared->digest, 32);
                for (i = 0; i < shared->workers; i++) {
                    if (shared->slots[i].pid <= 0
                        || kill(shared->slots[i].pid, 0) != 0
                        || (ngx_msec_int_t) (ngx_current_msec - shared->slots[i].heartbeat) > 5000
                        || ngx_memcmp(shared->slots[i].prepared, scdn_prepared->digest, 32) != 0)
                    { ready = 0; break; }
                }
                if (ready && ngx_memcmp(shared->active, scdn_prepared->digest, 32) != 0) {
                    ngx_memcpy(shared->active, scdn_prepared->digest, 32);
                    shared->generation++;
                }
            }
        }
    } else {
        if (scdn_error == NULL || strcmp(scdn_error, job->error) != 0) {
            ngx_log_error(NGX_LOG_WARN, event->log, 0,
                          "scdn_config candidate rejected: %s", job->error);
        }
        scdn_error = job->error;
        scdn_config_release(scdn_prepared); scdn_prepared = NULL;
    }
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    scdn_adopt();
}

static void
scdn_tick(ngx_event_t *event)
{
    scdn_job_t *job;
    if (ngx_exiting || ngx_quit || ngx_terminate) { return; }
    scdn_adopt();
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    scdn_main->shared->slots[ngx_worker].heartbeat = ngx_current_msec;
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    if (!scdn_busy) {
        job = scdn_task->ctx;
        job->path = (char *) scdn_main->file.data;
        job->cache = scdn_prepared != NULL ? scdn_prepared : scdn_current;
        job->cache->refs++;
        scdn_busy = 1;
        if (ngx_thread_task_post(scdn_main->threads, scdn_task) != NGX_OK) {
            scdn_busy = 0;
            scdn_config_release(job->cache); job->cache = NULL;
            scdn_error = "reader_task_unavailable";
        }
    }
    ngx_add_timer(event, scdn_main->interval);
}

static ngx_int_t
scdn_worker_init(ngx_cycle_t *cycle)
{
    ngx_core_conf_t *core;
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) { return NGX_OK; }
    scdn_main = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_scdn_config_module);
    if (scdn_main == NULL || scdn_main->file.data == NULL) { return NGX_OK; }
    core = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    scdn_current = scdn_main->bootstrap;
    scdn_current->refs++; /* master-pool cleanup owns the inherited reference */
    scdn_task = ngx_thread_task_alloc(cycle->pool, sizeof(scdn_job_t));
    if (scdn_task == NULL) { return NGX_ERROR; }
    scdn_task->handler = scdn_scan;
    scdn_task->event.handler = scdn_complete;
    scdn_task->event.data = scdn_task->ctx;
    scdn_task->event.log = cycle->log;
    ngx_memzero(&scdn_timer, sizeof(scdn_timer));
    scdn_timer.handler = scdn_tick;
    scdn_timer.log = cycle->log;
    scdn_timer.cancelable = 1;
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    scdn_main->shared->workers = core->worker_processes;
    scdn_main->shared->slots[ngx_worker].pid = ngx_pid;
    scdn_main->shared->slots[ngx_worker].heartbeat = ngx_current_msec;
    ngx_memcpy(scdn_main->shared->slots[ngx_worker].prepared, scdn_current->digest, 32);
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    ngx_add_timer(&scdn_timer, scdn_main->interval);
    return NGX_OK;
}

static void
scdn_worker_exit(ngx_cycle_t *cycle)
{
    (void) cycle;
    if (scdn_main == NULL || scdn_main->shared == NULL) { return; }
    if (scdn_timer.timer_set) { ngx_del_timer(&scdn_timer); }
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    if (scdn_main->shared->slots[ngx_worker].pid == ngx_pid) {
        scdn_main->shared->slots[ngx_worker].pid = 0;
    }
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    /* The process owns remaining pools, OpenSSL objects and any executing job. */
}

ngx_flag_t
scdn_config_local(ngx_http_request_t *r)
{
    struct sockaddr_storage peer;
    socklen_t length = sizeof(peer);
    if (getpeername(r->connection->fd, (struct sockaddr *) &peer, &length) != 0) { return 0; }
    if (peer.ss_family == AF_UNIX) { return 1; }
    if (peer.ss_family == AF_INET) {
        return (ntohl(((struct sockaddr_in *) &peer)->sin_addr.s_addr) >> 24) == 127;
    }
#if (NGX_HAVE_INET6)
    if (peer.ss_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *) &peer)->sin6_addr);
    }
#endif
    return 0;
}

static ngx_int_t
scdn_status(ngx_http_request_t *r)
{
    scdn_config_snapshot_t *snapshot;
    ngx_buf_t *buffer;
    ngx_chain_t chain;
    ngx_table_elt_t *header;
    ngx_int_t rc;
    ngx_uint_t generation, i;
    u_char revision[65];

    if (!scdn_config_local(r)) { return NGX_HTTP_FORBIDDEN; }
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) { return NGX_HTTP_NOT_ALLOWED; }
    if (r->args.len != 0 || r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->keepalive = 0; return NGX_HTTP_BAD_REQUEST;
    }
    snapshot = scdn_config_acquire();
    if (scdn_main == NULL || scdn_main->shared == NULL) { return NGX_HTTP_SERVICE_UNAVAILABLE; }
    buffer = ngx_create_temp_buf(r->pool, 1024);
    if (buffer == NULL) { scdn_config_release(snapshot); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_shmtx_lock(&scdn_main->slab->mutex);
    generation = scdn_main->shared->generation;
    for (i = 0; i < 32; i++) {
        revision[i * 2] = "0123456789abcdef"[scdn_main->shared->active[i] >> 4];
        revision[i * 2 + 1] = "0123456789abcdef"[scdn_main->shared->active[i] & 15];
    }
    revision[64] = 0;
    ngx_shmtx_unlock(&scdn_main->slab->mutex);
    buffer->last = ngx_snprintf(buffer->last, 1024,
        "{\"generation\":%ui,\"revision\":\"%s\",\"sites\":%ui,"
        "\"worker_pid\":%P,\"ready\":%s,\"last_error\":\"%s\",\"writes_source\":false,"
        "\"restarts_workers\":false}\n", generation, revision,
        snapshot != NULL ? snapshot->count : 0, ngx_pid, snapshot != NULL ? "true" : "false",
        scdn_error != NULL ? scdn_error : "");
    scdn_config_release(snapshot);
    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    header->hash = 1;
    ngx_str_set(&header->key, "Cache-Control"); ngx_str_set(&header->value, "no-store");
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = buffer->last - buffer->pos;
    buffer->last_buf = r == r->main; buffer->last_in_chain = 1;
    chain.buf = buffer; chain.next = NULL;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }
    return ngx_http_output_filter(r, &chain);
}
