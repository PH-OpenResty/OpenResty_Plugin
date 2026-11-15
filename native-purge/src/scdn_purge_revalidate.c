#include "scdn_purge.h"

/* Only failed/unfinished validation attempts need a retry deadline. This
 * bounded table is separate from the durable invalidation index: losing an
 * entry may cause an extra conditional GET, never resurrect a purged key. */
#define REVALIDATE_SLOTS 4096
typedef struct {
    u_char key[NGX_HTTP_CACHE_KEY_LEN];
    uintptr_t cache;
    ngx_msec_t next;
} revalidate_slot_t;

typedef struct {
    ngx_uint_t format;
    revalidate_slot_t slots[REVALIDATE_SLOTS];
} revalidate_shared_t;

typedef struct {
    ngx_http_request_t *request;
    ngx_http_upstream_t *upstream;
    ngx_int_t (*create)(ngx_http_request_t *r);
    ngx_int_t (*header)(ngx_http_request_t *r);
    ngx_int_t (*reinit)(ngx_http_request_t *r);
    void (*finalize)(ngx_http_request_t *r, ngx_int_t rc);
    ngx_str_t scope, resource;
    time_t interval, stale_updating, stale_error;
    ngx_msec_t deadline;
    ngx_flag_t attempted, invalidated, suppressed;
} revalidate_request_t;

typedef struct {
    scdn_purge_job_t job;
    ngx_pool_t *pool;
} revalidate_job_t;

static char revalidate_tag;
static uint64_t probes, unchanged, fetched, failures, suppressed, evictions;
static uint64_t invalidated, invalidate_failed;

static ngx_int_t revalidate_create(ngx_http_request_t *r);
static ngx_int_t revalidate_header(ngx_http_request_t *r);
static ngx_int_t revalidate_reinit(ngx_http_request_t *r);
static void revalidate_finalize(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t
revalidate_zone_init(ngx_shm_zone_t *zone, void *previous)
{
    scdn_purge_main_t *main=zone->data, *old=previous;
    revalidate_shared_t *shared;
    main->revalidate_slab=(ngx_slab_pool_t *)zone->shm.addr;
    if(old)main->revalidate_shared=old->revalidate_shared;
    else if(zone->shm.exists)main->revalidate_shared=main->revalidate_slab->data;
    else {
        shared=ngx_slab_calloc(main->revalidate_slab,sizeof(*shared));
        if(shared==NULL)return NGX_ERROR;
        shared->format=1;
        main->revalidate_shared=shared;main->revalidate_slab->data=shared;
    }
    shared=main->revalidate_shared;
    return shared && shared->format==1?NGX_OK:NGX_ERROR;
}

ngx_int_t
scdn_purge_revalidate_configure(ngx_conf_t *cf, scdn_purge_main_t *main)
{
    ngx_str_t name;
    name.len=main->zone->shm.name.len+sizeof(":revalidate")-1;
    name.data=ngx_pnalloc(cf->pool,name.len);
    if(name.data==NULL)return NGX_ERROR;
    ngx_memcpy(name.data,main->zone->shm.name.data,main->zone->shm.name.len);
    ngx_memcpy(name.data+main->zone->shm.name.len,":revalidate",sizeof(":revalidate")-1);
    main->revalidate_zone=ngx_shared_memory_add(cf,&name,512*1024,&revalidate_tag);
    if(main->revalidate_zone==NULL)return NGX_ERROR;
    main->revalidate_zone->data=main;
    main->revalidate_zone->init=revalidate_zone_init;
    return NGX_OK;
}

static revalidate_request_t *
revalidate_context(ngx_http_request_t *r)
{
    revalidate_request_t *context=ngx_http_get_module_ctx(r,ngx_http_scdn_purge_module);
    if(context && context->request==r && context->upstream==r->upstream)return context;
    return NULL;
}

ngx_int_t
scdn_purge_revalidate_attach(ngx_http_request_t *r,
    scdn_purge_location_t *location, ngx_str_t *scope, ngx_str_t *resource)
{
    ngx_http_upstream_t *u=r->upstream;
    ngx_http_upstream_conf_t *conf;
    revalidate_request_t *context;
    /* A key may also be evaluated in rewrite/log phases, before proxy exists. */
    if(u==NULL || u->conf==NULL || u->create_request==NULL)return NGX_OK;
    if(revalidate_context(r))return NGX_OK;
    if(u->conf->module.len!=sizeof("proxy")-1
       || ngx_memcmp(u->conf->module.data,"proxy",sizeof("proxy")-1)!=0) {
        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"scdn_purge_revalidate requires proxy_cache");
        return NGX_ERROR;
    }
    context=ngx_pcalloc(r->pool,sizeof(*context));
    conf=ngx_palloc(r->pool,sizeof(*conf));
    if(context==NULL || conf==NULL)return NGX_ERROR;
    *conf=*u->conf;
    conf->cache_revalidate=1;conf->cache_background_update=1;conf->cache_lock=1;
    /* Native unconditional stale flags would bypass the finite windows in
     * the cache header. Enable HTTP error flags only for an eligible request. */
    conf->cache_use_stale=NGX_CONF_BITMASK_SET;
    context->request=r;context->upstream=u;context->interval=location->revalidate;
    context->stale_updating=location->stale_updating;context->stale_error=location->stale_error;
    context->scope=*scope;context->resource=*resource;
    context->create=u->create_request;context->header=u->process_header;
    context->reinit=u->reinit_request;context->finalize=u->finalize_request;
    ngx_http_set_ctx(r,context,ngx_http_scdn_purge_module);
    u->conf=conf;u->create_request=revalidate_create;u->process_header=revalidate_header;
    u->reinit_request=revalidate_reinit;u->finalize_request=revalidate_finalize;
    return NGX_OK;
}

static ngx_flag_t
revalidate_due(ngx_http_request_t *r, time_t interval, ngx_msec_t *deadline)
{
    scdn_purge_main_t *main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    revalidate_shared_t *shared=main->revalidate_shared;
    revalidate_slot_t *slot, *chosen;
    ngx_http_cache_t *cache=r->cache;
    uintptr_t identity=(uintptr_t)cache->file_cache->sh;
    ngx_uint_t bucket,i;
    ngx_msec_t now=ngx_current_msec;
    ngx_flag_t due=1;
    bucket=((ngx_crc32_short(cache->key,NGX_HTTP_CACHE_KEY_LEN)
             ^ (uint32_t)(identity>>4))%(REVALIDATE_SLOTS/4))*4;
    ngx_shmtx_lock(&main->revalidate_slab->mutex);
    chosen=&shared->slots[bucket];
    for(i=0;i<4;i++) {
        slot=&shared->slots[bucket+i];
        if(slot->cache==identity
           && ngx_memcmp(slot->key,cache->key,NGX_HTTP_CACHE_KEY_LEN)==0) {
            chosen=slot;
            if((ngx_msec_int_t)(slot->next-now)>0)due=0;
            goto found;
        }
        if(slot->cache==0 || (ngx_msec_int_t)(slot->next-chosen->next)<0)chosen=slot;
    }
    if(chosen->cache && (ngx_msec_int_t)(chosen->next-now)>0)evictions++;
found:
    if(due) {
        /* Publish identity last so a killed writer leaves, at worst, a lost
         * cooldown. Cache contents and purge epochs are never modified here. */
        chosen->cache=0;
        ngx_memory_barrier();
        ngx_memcpy(chosen->key,cache->key,NGX_HTTP_CACHE_KEY_LEN);
        chosen->next=now+(ngx_msec_t)interval*1000;
        *deadline=chosen->next;
        ngx_memory_barrier();
        chosen->cache=identity;
    }
    ngx_shmtx_unlock(&main->revalidate_slab->mutex);
    return due;
}

static void
revalidate_release(ngx_http_request_t *r, revalidate_request_t *context)
{
    scdn_purge_main_t *main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    revalidate_shared_t *shared=main->revalidate_shared;
    ngx_http_cache_t *cache=r->cache;
    revalidate_slot_t *slot;
    uintptr_t identity;
    ngx_uint_t i,bucket;
    if(context->deadline==0 || cache==NULL)return;
    identity=(uintptr_t)cache->file_cache->sh;
    bucket=((ngx_crc32_short(cache->key,NGX_HTTP_CACHE_KEY_LEN)
             ^ (uint32_t)(identity>>4))%(REVALIDATE_SLOTS/4))*4;
    ngx_shmtx_lock(&main->revalidate_slab->mutex);
    for(i=0;i<4;i++) {
        slot=&shared->slots[bucket+i];
        if(slot->cache==identity && slot->next==context->deadline
           && ngx_memcmp(slot->key,cache->key,NGX_HTTP_CACHE_KEY_LEN)==0) {
            slot->next=0;break;
        }
    }
    ngx_shmtx_unlock(&main->revalidate_slab->mutex);
}

static ngx_int_t
revalidate_create(ngx_http_request_t *r)
{
    revalidate_request_t *context=revalidate_context(r);
    ngx_http_upstream_t *u=r->upstream;
    if(context==NULL)return NGX_ERROR;
    if(r->cache && u->cache_status==NGX_HTTP_CACHE_EXPIRED) {
        if(r->background && !revalidate_due(r,context->interval,&context->deadline)) {
            context->suppressed=1;suppressed++;
            /* The foreground has already received stale content. Only this
             * background subrequest ends; no network connection is created. */
            return NGX_ERROR;
        }
        context->attempted=1;probes++;
    }
    return context->create(r);
}

static void
revalidate_complete(ngx_event_t *event)
{
    revalidate_job_t *task=event->data;
    if(task->job.status==200)invalidated++;
    else {
        invalidate_failed++;
        ngx_log_error(NGX_LOG_ERR,event->log,0,"scdn_purge origin invalidation failed: %s",task->job.error);
    }
    ngx_destroy_pool(task->pool);
}

static void
revalidate_invalidate(ngx_http_request_t *r, revalidate_request_t *context)
{
    scdn_purge_main_t *main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    ngx_pool_t *pool;
    ngx_thread_task_t *thread;
    revalidate_job_t *task;
    scdn_purge_operation_t *operation;
    if(context->invalidated)return;
    context->invalidated=1;
    pool=ngx_create_pool(4096,r->connection->log);
    if(pool==NULL)goto failed;
    thread=ngx_thread_task_alloc(pool,sizeof(*task));
    if(thread==NULL)goto destroy;
    task=thread->ctx;task->pool=pool;task->job.main=main;task->job.count=1;
    operation=&task->job.operations[0];operation->mode='E';
    operation->scope.len=context->scope.len;operation->key.len=context->resource.len;
    operation->scope.data=ngx_pnalloc(pool,operation->scope.len+operation->key.len);
    if(operation->scope.data==NULL)goto destroy;
    operation->key.data=operation->scope.data+operation->scope.len;
    ngx_memcpy(operation->scope.data,context->scope.data,operation->scope.len);
    ngx_memcpy(operation->key.data,context->resource.data,operation->key.len);
    /* Independent pool/log: neither the thread nor completion retains a
     * request/connection that a disconnected client could free. */
    pool->log=ngx_cycle->log;
    thread->handler=scdn_purge_commit;thread->event.handler=revalidate_complete;
    thread->event.data=task;thread->event.log=ngx_cycle->log;
    if(ngx_thread_task_post(main->threads,thread)==NGX_OK)return;
destroy:
    ngx_destroy_pool(pool);
failed:
    invalidate_failed++;
    ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"scdn_purge origin invalidation queue unavailable");
}

static ngx_int_t
revalidate_header(ngx_http_request_t *r)
{
    revalidate_request_t *context=revalidate_context(r);
    ngx_http_upstream_t *u=r->upstream;
    ngx_http_cache_t *cache=r->cache;
    ngx_table_elt_t *empty_etag;
    ngx_int_t rc;
    ngx_uint_t status;
    time_t valid,ceiling;
    ngx_flag_t unusable;
    if(context==NULL)return NGX_ERROR;
    rc=context->header(r);
    /* Proxy switches its parser after reading a status line, on interim
     * responses and on retries. Keep wrapping its actual current parser. */
    if(u->process_header!=revalidate_header)context->header=u->process_header;
    u->process_header=revalidate_header;
    if(rc!=NGX_OK || cache==NULL)return rc;
    if(r->cached) {
        if(u->cache_status==NGX_HTTP_CACHE_REVALIDATED) {
            /* A 304 may omit freshness headers. Nginx reparses the stored
             * response in that case; retain its shorter lifetime and cap the
             * result before the core writes the refreshed cache metadata. */
            valid=cache->valid_sec;
            if(valid==0) {
                valid=ngx_http_file_cache_valid(u->conf->cache_valid,u->headers_in.status_n);
                if(valid)valid+=ngx_time();
            }
            ceiling=ngx_time()+context->interval;
            cache->valid_sec=valid?ngx_min(valid,ceiling):ceiling;
            cache->updating_sec=context->stale_updating;cache->error_sec=context->stale_error;
        }
        return rc;
    }
    status=u->headers_in.status_n;
    if(status==NGX_HTTP_OK || status==NGX_HTTP_PARTIAL_CONTENT) {
        /* Core file_cache_set_header copies even a zero-length ETag. Supply
         * non-null storage without adding a response header or validator. */
        if(u->headers_in.etag==NULL) {
            empty_etag=ngx_pcalloc(r->pool,sizeof(*empty_etag));
            if(empty_etag==NULL)return NGX_ERROR;
            empty_etag->value.data=(u_char *)"";
            u->headers_in.etag=empty_etag;
        }
    } else if(status!=NGX_HTTP_NOT_MODIFIED) {
        /* The core explicitly nulls cache->etag for other statuses. They
         * also must not replace the successful representation we monitor. */
        u->cacheable=0;
    }
    if(status>=500 || status==NGX_HTTP_TOO_MANY_REQUESTS) {
        /* Even a mistaken public/max-age header on an error must not replace
         * the last successful object with a cached 5xx/429 response. */
        u->cacheable=0;
        if(u->cache_status==NGX_HTTP_CACHE_EXPIRED && cache->stale_error) {
            switch(status) {
            case 500: u->conf->cache_use_stale|=NGX_HTTP_UPSTREAM_FT_HTTP_500;break;
            case 502: u->conf->cache_use_stale|=NGX_HTTP_UPSTREAM_FT_HTTP_502;break;
            case 503: u->conf->cache_use_stale|=NGX_HTTP_UPSTREAM_FT_HTTP_503;break;
            case 504: u->conf->cache_use_stale|=NGX_HTTP_UPSTREAM_FT_HTTP_504;break;
            }
        }
        return rc;
    }
    unusable=!u->cacheable || u->headers_in.no_cache || u->headers_in.expired;
    valid=cache->valid_sec;
    if(valid==0 && status!=NGX_HTTP_NOT_MODIFIED) {
        valid=ngx_http_file_cache_valid(u->conf->cache_valid,status);
        if(valid)valid+=ngx_time();
    }
    if(status!=NGX_HTTP_NOT_MODIFIED && valid==0)unusable=1;
    if(unusable || (status>=400 && status<500)) {
        cache->stale_error=0;cache->stale_updating=0;
    }
    if(u->cache_status==NGX_HTTP_CACHE_EXPIRED
       && (unusable || (status>=400 && status<500)))
        revalidate_invalidate(r,context);
    /* The native 304 path would otherwise restore the old response's long
     * Cache-Control after a no-store/cookie validation. Do not renew it, even
     * if the independent durable invalidation job cannot commit yet. */
    if(status==NGX_HTTP_NOT_MODIFIED && unusable)return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    if(!unusable) {
        ceiling=ngx_time()+context->interval;
        /* This runs before Nginx's 304 branch captures valid_sec, and before
         * a 200 is persisted. A response header cannot postpone the check. */
        if(valid || status!=NGX_HTTP_NOT_MODIFIED)
            cache->valid_sec=valid?ngx_min(valid,ceiling):ceiling;
        cache->updating_sec=context->stale_updating;
        cache->error_sec=context->stale_error;
    }
    return rc;
}

static ngx_int_t
revalidate_reinit(ngx_http_request_t *r)
{
    revalidate_request_t *context=revalidate_context(r);
    ngx_http_upstream_t *u=r->upstream;
    ngx_int_t rc;
    if(context==NULL)return NGX_ERROR;
    rc=context->reinit(r);
    if(u->process_header!=revalidate_header)context->header=u->process_header;
    u->process_header=revalidate_header;
    return rc;
}

static void
revalidate_finalize(ngx_http_request_t *r, ngx_int_t rc)
{
    revalidate_request_t *context=revalidate_context(r);
    if(context==NULL)return;
    if(context->attempted && !context->suppressed) {
        if(rc==0 && r->upstream->cache_status==NGX_HTTP_CACHE_REVALIDATED) {
            unchanged++;revalidate_release(r,context);
        }
        else if(rc==0 && r->cache && r->cache->updated
                && r->upstream->headers_in.status_n==NGX_HTTP_OK) {
            fetched++;revalidate_release(r,context);
        }
        else failures++;
    }
    context->finalize(r,rc);
}

u_char *
scdn_purge_revalidate_status(u_char *p, u_char *last)
{
    return ngx_snprintf(p,last-p,
        ",\"worker_revalidate\":{\"probes\":%uL,\"not_modified\":%uL,\"fetched\":%uL,"
        "\"failures\":%uL,\"suppressed\":%uL,\"cooldown_evictions\":%uL,"
        "\"invalidated\":%uL,\"invalidate_failed\":%uL}",
        probes,unchanged,fetched,failures,suppressed,evictions,invalidated,invalidate_failed);
}
