#include "auth_internal.h"

uint64_t auth_now(void) {
    struct timespec now;
#ifdef CLOCK_BOOTTIME
    if (clock_gettime(CLOCK_BOOTTIME, &now)) return 0;
#else
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
#endif
    return (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
}
static void bucket_insert(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {
    ngx_rbtree_node_t **link;
    for (;;) {
        if (node->key < root->key) link = &root->left;
        else if (node->key > root->key) link = &root->right;
        else link = ngx_memcmp(((auth_bucket *) node)->key, ((auth_bucket *) root)->key, 32) < 0 ? &root->left : &root->right;
        if (*link == sentinel) break;
        root = *link;
    }
    *link = node; node->parent = root; node->left = sentinel; node->right = sentinel; ngx_rbt_red(node);
}
static void attempt_insert(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {
    ngx_rbtree_node_t **link;
    for (;;) {
        if (node->key < root->key) link = &root->left;
        else if (node->key > root->key) link = &root->right;
        else link = ngx_memcmp(((auth_attempt *) node)->id, ((auth_attempt *) root)->id, 16) < 0 ? &root->left : &root->right;
        if (*link == sentinel) break;
        root = *link;
    }
    *link = node; node->parent = root; node->left = sentinel; node->right = sentinel; ngx_rbt_red(node);
}
static auth_bucket *find_bucket(auth_main *m, const u_char *key) {
    ngx_rbtree_node_t *node = m->shared->buckets.root, *sentinel = m->shared->buckets.sentinel;
    ngx_rbtree_key_t hash = ngx_crc32_short((u_char *) key, 32);
    ngx_int_t compared;
    while (node != sentinel) {
        if (hash < node->key) node = node->left;
        else if (hash > node->key) node = node->right;
        else {
            compared = ngx_memcmp(key, ((auth_bucket *) node)->key, 32);
            if (!compared) return (auth_bucket *) node;
            node = compared < 0 ? node->left : node->right;
        }
    }
    return NULL;
}
static auth_attempt *find_attempt(auth_main *m, const u_char *id) {
    ngx_rbtree_node_t *node = m->shared->attempts.root, *sentinel = m->shared->attempts.sentinel;
    ngx_rbtree_key_t hash = ngx_crc32_short((u_char *) id, 16);
    ngx_int_t compared;
    while (node != sentinel) {
        if (hash < node->key) node = node->left;
        else if (hash > node->key) node = node->right;
        else {
            compared = ngx_memcmp(id, ((auth_attempt *) node)->id, 16);
            if (!compared) return (auth_attempt *) node;
            node = compared < 0 ? node->left : node->right;
        }
    }
    return NULL;
}
static void touch(auth_main *m, auth_bucket *bucket, uint64_t now) {
    ngx_queue_remove(&bucket->expiry); bucket->expires = now + AUTH_TTL;
    ngx_queue_insert_tail(&m->shared->bucket_expiry, &bucket->expiry);
}
static auth_bucket *bucket(auth_main *m, const u_char *key, uint64_t now) {
    auth_bucket *value = find_bucket(m, key);
    if (value) { touch(m, value, now); return value; }
    if (m->shared->bucket_count >= m->max_entries) return NULL;
    value = ngx_slab_calloc_locked(m->slab, sizeof(*value));
    if (!value) return NULL;
    ngx_memcpy(value->key, key, 32); value->node.key = ngx_crc32_short(value->key, 32);
    value->expires = now + AUTH_TTL;
    ngx_rbtree_insert(&m->shared->buckets, &value->node);
    ngx_queue_insert_tail(&m->shared->bucket_expiry, &value->expiry);
    m->shared->bucket_count++;
    return value;
}
static ngx_int_t bucket_key(auth_request *ctx, ngx_uint_t kind, u_char *out) {
    u_char data[128]; size_t n = 0;
    data[n++] = (u_char) ctx->realm->id.len;
    ngx_memcpy(data + n, ctx->realm->id.data, ctx->realm->id.len); n += ctx->realm->id.len;
    data[n++] = (u_char) kind;
    if (kind == 1 || kind == 2) {
        data[n++] = ctx->ip.family == AF_INET ? 4 : 6;
        ngx_memcpy(data + n, ctx->ip.bytes, 16); n += 16;
    }
    if (kind >= 2) { ngx_memcpy(data + n, ctx->subject, 32); n += 32; }
    return auth_hmac(ctx->realm, "bucket", data, n, out);
}
static ngx_int_t subject_keys(auth_realm *realm, const u_char *ip, const u_char *subject, u_char *combo, u_char *account) {
    u_char data[64];
    ngx_memcpy(data, ip, 32); ngx_memcpy(data + 32, subject, 32);
    if (auth_hmac(realm, "combo", data, 64, combo) != NGX_OK) return NGX_ERROR;
    return auth_hmac(realm, "account", subject, 32, account);
}
static void remove_attempt(auth_main *m, auth_attempt *a) {
    auth_bucket *refs[] = {a->total, a->ip, a->combo, a->account};
    ngx_uint_t i;
    for (i = 0; i < 4; i++) if (refs[i] && refs[i]->active) refs[i]->active--;
    ngx_rbtree_delete(&m->shared->attempts, &a->node); ngx_queue_remove(&a->expiry);
    if (m->shared->active) m->shared->active--;
    ngx_slab_free_locked(m->slab, a);
}
static void sweep_locked(auth_main *m, uint64_t now) {
    ngx_uint_t budget = 64;
    ngx_queue_t *q;
    auth_attempt *a;
    auth_bucket *b;
    while (budget-- && !ngx_queue_empty(&m->shared->attempt_expiry)) {
        q = ngx_queue_head(&m->shared->attempt_expiry); a = ngx_queue_data(q, auth_attempt, expiry);
        if (a->deadline > now) break;
        remove_attempt(m, a); m->shared->expired++;
    }
    budget = 64;
    while (budget-- && !ngx_queue_empty(&m->shared->bucket_expiry)) {
        q = ngx_queue_head(&m->shared->bucket_expiry); b = ngx_queue_data(q, auth_bucket, expiry);
        if (b->expires > now) break;
        if (b->active) { touch(m, b, now); continue; }
        ngx_rbtree_delete(&m->shared->buckets, &b->node); ngx_queue_remove(&b->expiry);
        m->shared->bucket_count--; ngx_slab_free_locked(m->slab, b);
    }
}
void auth_sweep(auth_main *m) {
    uint64_t now = auth_now();
    if (!now || !m->slab || !m->shared) return;
    ngx_shmtx_lock(&m->slab->mutex); sweep_locked(m, now); ngx_shmtx_unlock(&m->slab->mutex);
}
ngx_int_t auth_state_init(ngx_shm_zone_t *zone, void *old) {
    auth_main *m = zone->data, *previous = old;
    m->slab = (ngx_slab_pool_t *) zone->shm.addr;
    if (previous) m->shared = previous->shared;
    else if (zone->shm.exists) m->shared = m->slab->data;
    else {
        m->shared = ngx_slab_calloc(m->slab, sizeof(*m->shared));
        if (!m->shared) return NGX_ERROR;
        m->shared->magic = 0x41555431;
        ngx_memcpy(m->shared->key_tag, m->key_tag, 32);
        ngx_rbtree_init(&m->shared->buckets, &m->shared->bucket_sentinel, bucket_insert);
        ngx_rbtree_init(&m->shared->attempts, &m->shared->attempt_sentinel, attempt_insert);
        ngx_queue_init(&m->shared->bucket_expiry); ngx_queue_init(&m->shared->attempt_expiry);
        m->slab->data = m->shared;
    }
    return m->shared && m->shared->magic == 0x41555431 && !CRYPTO_memcmp(m->shared->key_tag, m->key_tag, 32) ? NGX_OK : NGX_ERROR;
}
static ngx_flag_t take(auth_bucket *b, uint64_t now, ngx_uint_t rate, ngx_uint_t burst) {
    uint64_t interval = (60000 + rate - 1) / rate, tat = b->tat > now ? b->tat : now;
    return tat <= now + interval * (burst - 1);
}
static void charge(auth_bucket *b, uint64_t now, ngx_uint_t rate) {
    b->tat = (b->tat > now ? b->tat : now) + (60000 + rate - 1) / rate;
}
ngx_int_t auth_reserve(auth_request *ctx) {
    auth_main *m = ctx->main;
    uint64_t now = auth_now();
    u_char ip_key[32], realm_key[32];
    auth_bucket *ip, *total;
    auth_attempt *a;
    ngx_int_t rc = NGX_HTTP_SERVICE_UNAVAILABLE;
    if (!now || bucket_key(ctx, 0, realm_key) != NGX_OK || bucket_key(ctx, 1, ip_key) != NGX_OK) return rc;
    ngx_shmtx_lock(&m->slab->mutex); sweep_locked(m, now);
    total = bucket(m, realm_key, now);
    ip = find_bucket(m, ip_key);
    if (ip && ip->ban_until > now && !ctx->observe) { rc = NGX_HTTP_FORBIDDEN; goto done; }
    if (!total || m->shared->active >= m->max_active || total->active >= 128) goto done;
    if (!take(total, now, ctx->realm->rate * 32, ctx->realm->burst * 16)) { rc = NGX_HTTP_TOO_MANY_REQUESTS; goto done; }
    ip = bucket(m, ip_key, now);
    if (!ip || ip->active >= 4) goto done;
    if (!take(ip, now, ctx->realm->rate, ctx->realm->burst) && !ctx->observe) { rc = NGX_HTTP_TOO_MANY_REQUESTS; goto done; }
    if (find_attempt(m, ctx->id)) goto done;
    a = ngx_slab_calloc_locked(m->slab, sizeof(*a));
    if (!a) goto done;
    ngx_memcpy(a->id, ctx->id, 16); a->node.key = ngx_crc32_short(a->id, 16);
    ngx_memcpy(a->realm, ctx->realm->id.data, ctx->realm->id.len);
    ngx_memcpy(a->revision, ctx->realm->revision.data, ctx->realm->revision.len);
    a->deadline = now + AUTH_DEADLINE; a->ip = ip; a->total = total; a->flow = ctx->flow; a->fence = ip->fence; a->observe = ctx->observe;
    ip->active++; total->active++; m->shared->active++;
    if (now - ip->window_start >= ctx->realm->window) {
        ip->window_start = now; ip->requests = ip->failures = ip->factor_failures = ip->rejected = ip->successes = 0; ip->distinct = 0;
    }
    ip->requests++; charge(ip, now, ctx->realm->rate); charge(total, now, ctx->realm->rate * 32);
    ngx_rbtree_insert(&m->shared->attempts, &a->node); ngx_queue_insert_tail(&m->shared->attempt_expiry, &a->expiry);
    ctx->reserved = 1; ctx->expires = ngx_time() + 15; m->shared->admitted++; rc = NGX_OK;
done:
    if (rc != NGX_OK) m->shared->rejected++;
    ngx_shmtx_unlock(&m->slab->mutex); return rc;
}
ngx_int_t auth_reserve_subject(auth_request *ctx) {
    auth_main *m = ctx->main;
    uint64_t now = auth_now();
    u_char combo_key[32], account_key[32], ip_key[32];
    auth_attempt *a;
    auth_bucket *combo, *account;
    ngx_int_t rc = NGX_HTTP_SERVICE_UNAVAILABLE;
    if (!now || bucket_key(ctx, 1, ip_key) != NGX_OK) return rc;
    if (ctx->subject_ready && subject_keys(ctx->realm, ip_key, ctx->subject, combo_key, account_key) != NGX_OK) return rc;
    ngx_shmtx_lock(&m->slab->mutex);
    a = find_attempt(m, ctx->id);
    if (!a || a->deadline <= now) goto done;
    if (a->fence != a->ip->fence || (a->ip->ban_until > now && !ctx->observe)) { rc = NGX_HTTP_FORBIDDEN; goto done; }
    if (!ctx->subject_ready) { rc = NGX_OK; goto done; }
    if (a->combo) { rc = NGX_OK; goto done; }
    combo = bucket(m, combo_key, now); account = bucket(m, account_key, now);
    if (!combo || !account || combo->active >= 2 || account->active >= 8) goto done;
    if (combo->cooldown_until > now && !ctx->observe) { rc = NGX_HTTP_TOO_MANY_REQUESTS; goto done; }
    a->combo = combo; a->account = account; combo->active++; account->active++;
    ngx_memcpy(a->subject, ctx->subject, 32); rc = NGX_OK;
done:
    ngx_shmtx_unlock(&m->slab->mutex); return rc;
}
void auth_release(auth_request *ctx) {
    auth_attempt *a;
    if (!ctx->reserved || !ctx->main->slab) return;
    ngx_shmtx_lock(&ctx->main->slab->mutex);
    a = find_attempt(ctx->main, ctx->id);
    if (a) remove_attempt(ctx->main, a);
    ngx_shmtx_unlock(&ctx->main->slab->mutex); ctx->reserved = 0;
}
static void distinct(auth_bucket *bucket, const u_char *subject) {
    ngx_uint_t i;
    for (i = 0; i < bucket->distinct; i++) if (!ngx_memcmp(bucket->subjects[i], subject, 32)) return;
    if (bucket->distinct < AUTH_UNIQUE) ngx_memcpy(bucket->subjects[bucket->distinct++], subject, 32);
}
void auth_outcome(auth_request *ctx, ngx_uint_t outcome) {
    auth_main *m = ctx->main;
    auth_attempt *a;
    auth_bucket *ip, *combo;
    uint64_t now = auth_now();
    if (!ctx->reserved || !now || !outcome) return;
    ngx_shmtx_lock(&m->slab->mutex);
    a = find_attempt(m, ctx->id);
    if (!a || a->deadline <= now || a->ip->fence != a->fence) goto done;
    ip = a->ip; combo = a->combo;
    if (now - ip->window_start >= ctx->realm->window) goto done;
    if (outcome == AUTH_RESULT_CREDENTIALS || outcome == AUTH_RESULT_FACTOR) {
        if (outcome == AUTH_RESULT_CREDENTIALS) ip->failures++; else ip->factor_failures++;
        if (combo) {
            if (now - combo->window_start >= ctx->realm->window) { combo->window_start = now; combo->failures = combo->factor_failures = 0; }
            if (outcome == AUTH_RESULT_CREDENTIALS) combo->failures++; else combo->factor_failures++;
            if (combo->failures >= ctx->realm->login_limit || combo->factor_failures >= ctx->realm->login_limit) combo->cooldown_until = now + ctx->realm->cooldown;
        }
        if (a->account && outcome == AUTH_RESULT_CREDENTIALS) {
            if (now - a->account->window_start >= ctx->realm->window) {
                a->account->window_start = now; a->account->failures = 0; a->account->distinct = 0;
            }
            a->account->failures++; distinct(a->account, ip->key);
        }
    } else if (outcome == AUTH_RESULT_REG_POLICY || outcome == AUTH_RESULT_EMAIL_CODE) {
        if (ctx->flow != AUTH_REGISTER && ctx->flow != AUTH_MAIL && ctx->flow != AUTH_OAUTH) goto done;
        ip->rejected++;
        if (ctx->subject_ready) distinct(ip, ctx->subject);
        if (ip->ban_until <= now && ip->rejected >= ctx->realm->reject_limit
            && ip->distinct >= ctx->realm->distinct_limit && ip->rejected * 10 >= ip->requests * 9) {
            ip->ban_until = now + ctx->realm->ban_time; m->shared->banned++;
        }
    } else if (outcome == AUTH_RESULT_LOGIN_OK || outcome == AUTH_RESULT_REG_OK) {
        ip->successes++;
        if (combo) { combo->failures = combo->factor_failures = 0; combo->cooldown_until = 0; }
    }
    touch(m, ip, now);
done:
    ngx_shmtx_unlock(&m->slab->mutex);
}
ngx_int_t auth_precreate(auth_main *m, auth_realm *realm, const u_char *id, const u_char *subject, ngx_flag_t verified) {
    auth_attempt *a;
    auth_bucket *combo, *account;
    u_char ip_key[32], combo_key[32], account_key[32], empty[32] = {0};
    uint64_t now = auth_now();
    ngx_int_t rc = NGX_HTTP_FORBIDDEN;
    if (!verified || !now) return rc;
    ngx_shmtx_lock(&m->slab->mutex);
    a = find_attempt(m, id);
    if (!a || ngx_strlen(a->realm) != realm->id.len || ngx_memcmp(a->realm, realm->id.data, realm->id.len)) goto first_done;
    ngx_memcpy(ip_key, a->ip->key, 32); rc = NGX_OK;
first_done:
    ngx_shmtx_unlock(&m->slab->mutex);
    if (rc != NGX_OK || subject_keys(realm, ip_key, subject, combo_key, account_key) != NGX_OK) return NGX_HTTP_FORBIDDEN;
    rc = NGX_HTTP_FORBIDDEN;
    ngx_shmtx_lock(&m->slab->mutex);
    a = find_attempt(m, id);
    if (!a || a->deadline <= now || a->fence != a->ip->fence || (a->ip->ban_until > now && !a->observe)
        || (a->flow != AUTH_REGISTER && a->flow != AUTH_OAUTH)
        || ngx_strlen(a->revision) != realm->revision.len || ngx_memcmp(a->revision, realm->revision.data, realm->revision.len)) goto done;
    if (ngx_memcmp(a->subject, empty, 32) && ngx_memcmp(a->subject, subject, 32)) goto done;
    if (!a->combo) {
        combo = bucket(m, combo_key, now); account = bucket(m, account_key, now);
        if (!combo || !account || combo->active >= 2 || account->active >= 8 || (combo->cooldown_until > now && !a->observe)) goto done;
        combo->active++; account->active++; a->combo = combo; a->account = account;
    }
    ngx_memcpy(a->subject, subject, 32);
    if (!a->precreated) { a->precreated = 1; m->shared->precreated++; }
    rc = NGX_OK;
done:
    ngx_shmtx_unlock(&m->slab->mutex); return rc;
}
ngx_int_t auth_unban(auth_main *m, auth_realm *realm, scdn_sec_ip *ip) {
    auth_request ctx;
    auth_bucket *bucket;
    u_char key[32];
    ngx_memzero(&ctx, sizeof(ctx)); ctx.realm = realm; ctx.ip = *ip;
    if (bucket_key(&ctx, 1, key) != NGX_OK) return NGX_ERROR;
    ngx_shmtx_lock(&m->slab->mutex);
    bucket = find_bucket(m, key);
    if (bucket) {
        bucket->ban_until = 0; bucket->fence++;
        bucket->window_start = auth_now(); bucket->requests = bucket->failures = bucket->factor_failures = bucket->rejected = bucket->successes = 0; bucket->distinct = 0;
    }
    ngx_shmtx_unlock(&m->slab->mutex); return NGX_OK;
}
