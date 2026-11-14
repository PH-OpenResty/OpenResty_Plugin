#include "scdn_edge.h"

ngx_int_t
scdn_edge_zone_init(ngx_shm_zone_t *zone, void *old)
{
    scdn_edge_main_t *main = zone->data, *previous = old;
    main->slab = (ngx_slab_pool_t *) zone->shm.addr;
    if (previous != NULL) { main->shared = previous->shared; }
    else if (zone->shm.exists) { main->shared = main->slab->data; }
    else {
        main->shared = ngx_slab_calloc(main->slab, sizeof(scdn_edge_shared_t));
        main->slab->data = main->shared;
    }
    return main->shared != NULL ? NGX_OK : NGX_ERROR;
}

scdn_edge_counter_t *
scdn_edge_counter(ngx_http_request_t *r, ngx_str_t *id)
{
    scdn_edge_main_t *main;
    scdn_edge_counter_t *counter = NULL;
    ngx_uint_t i;
    main = ngx_http_get_module_main_conf(r, ngx_http_scdn_edge_module);
    if (main->shared == NULL) { return NULL; }
    ngx_shmtx_lock(&main->slab->mutex);
    for (i = 0; i < main->shared->count; i++) {
        if (main->shared->counters[i].length == id->len
            && ngx_memcmp(main->shared->counters[i].id, id->data, id->len) == 0)
        { counter = &main->shared->counters[i]; break; }
    }
    if (counter == NULL && main->shared->count < SCDN_EDGE_COUNTERS) {
        counter = &main->shared->counters[main->shared->count++];
        counter->length = id->len;
        ngx_memcpy(counter->id, id->data, id->len);
    }
    ngx_shmtx_unlock(&main->slab->mutex);
    return counter;
}

ngx_int_t
scdn_edge_record(ngx_http_request_t *r)
{
    scdn_edge_request_t *request;
    scdn_edge_counter_t *counter;
    ngx_uint_t status, cache = 0;
    if (r != r->main) { return NGX_OK; }
    request = scdn_edge_request(r);
    if (request == NULL || request->recorded || request->counter == NULL) { return NGX_OK; }
    request->recorded = 1;
    counter = request->counter;
    status = (r->err_status ? r->err_status : r->headers_out.status) / 100;
    if (status > 5) { status = 0; }
#if (NGX_HTTP_CACHE)
    if (r->upstream != NULL && r->upstream->cache_status > 0 && r->upstream->cache_status <= 7) {
        cache = r->upstream->cache_status;
    }
#endif
    (void) ngx_atomic_fetch_add(&counter->requests, 1);
    (void) ngx_atomic_fetch_add(&counter->bytes, (ngx_atomic_int_t) r->connection->sent);
    (void) ngx_atomic_fetch_add(&counter->status[status], 1);
    (void) ngx_atomic_fetch_add(&counter->cache[cache], 1);
    return NGX_OK;
}

ngx_int_t
scdn_edge_metrics(ngx_http_request_t *r)
{
    static const char *names[] = { "none", "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED", "HIT" };
    scdn_edge_main_t *main;
    scdn_edge_counter_t *counter;
    ngx_buf_t *buffer;
    ngx_chain_t chain;
    ngx_str_t id;
    ngx_int_t rc;
    ngx_uint_t i, j, count;
    if (!scdn_config_local(r)) { return NGX_HTTP_FORBIDDEN; }
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) { return NGX_HTTP_NOT_ALLOWED; }
    if (r->args.len != 0 || r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->keepalive = 0; return NGX_HTTP_BAD_REQUEST;
    }
    main = ngx_http_get_module_main_conf(r, ngx_http_scdn_edge_module);
    if (main->shared == NULL) { return NGX_HTTP_SERVICE_UNAVAILABLE; }
    ngx_shmtx_lock(&main->slab->mutex); count = main->shared->count; ngx_shmtx_unlock(&main->slab->mutex);
    buffer = ngx_create_temp_buf(r->pool, 1024 + count * 4096);
    if (buffer == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
        "# TYPE scdn_edge_requests_total counter\n# TYPE scdn_edge_bytes_total counter\n"
        "# TYPE scdn_edge_responses_total counter\n# TYPE scdn_edge_cache_requests_total counter\n");
    for (i = 0; i < count; i++) {
        counter = &main->shared->counters[i];
        id.data = counter->id; id.len = counter->length;
        buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
            "scdn_edge_requests_total{site=\"%V\"} %uA\nscdn_edge_bytes_total{site=\"%V\"} %uA\n",
            &id, counter->requests, &id, counter->bytes);
        for (j = 0; j < 6; j++) {
            buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
                "scdn_edge_responses_total{site=\"%V\",class=\"%uixx\"} %uA\n", &id, j, counter->status[j]);
        }
        for (j = 0; j < 8; j++) {
            buffer->last = ngx_snprintf(buffer->last, buffer->end - buffer->last,
                "scdn_edge_cache_requests_total{site=\"%V\",status=\"%s\"} %uA\n", &id, names[j], counter->cache[j]);
        }
    }
    ngx_str_set(&r->headers_out.content_type, "text/plain; version=0.0.4");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = buffer->last - buffer->pos;
    buffer->last_buf = r == r->main; buffer->last_in_chain = 1;
    chain.buf = buffer; chain.next = NULL;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }
    return ngx_http_output_filter(r, &chain);
}

ngx_flag_t
scdn_edge_tier(ngx_http_request_t *r, scdn_edge_request_t *request)
{
    scdn_edge_main_t *main;
    scdn_edge_hot_t *entry;
    ngx_md5_t hash;
    u_char digest[16];
    ngx_uint_t index;
    if (request->tier_done) { return request->tier_hot; }
    request->tier_done = 1;
    if (request->site->tier_hits == 0) { return 0; }
    main = ngx_http_get_module_main_conf(r, ngx_http_scdn_edge_module);
    ngx_md5_init(&hash);
    ngx_md5_update(&hash, request->site->id.data, request->site->id.len);
    ngx_md5_update(&hash, (u_char *) "\0", 1);
    ngx_md5_update(&hash, r->headers_in.server.data, r->headers_in.server.len);
    ngx_md5_update(&hash, (u_char *) "\0", 1);
    ngx_md5_update(&hash, r->uri.data, r->uri.len);
    ngx_md5_final(digest, &hash);
    index = (((ngx_uint_t) digest[0] << 8) | digest[1]) % SCDN_EDGE_HOT;
    entry = &main->shared->hot[index];
    ngx_shmtx_lock(&main->slab->mutex);
    if (!entry->used || ngx_memcmp(entry->digest, digest, 16) != 0
        || (ngx_msec_int_t) (ngx_current_msec - entry->start) >= (ngx_msec_int_t) request->site->tier_window)
    {
        ngx_memcpy(entry->digest, digest, 16);
        entry->start = ngx_current_msec; entry->hits = 0; entry->used = 1;
    }
    if (entry->hits < 1000000) { entry->hits++; }
    request->tier_hot = entry->hits >= request->site->tier_hits;
    ngx_shmtx_unlock(&main->slab->mutex);
    return request->tier_hot;
}
