#ifndef SCDN_AUTH_INTERNAL_H
#define SCDN_AUTH_INTERNAL_H
#include "scdn_auth.h"
#include "scdn_security.h"
#include <json-c/json.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define AUTH_REALMS 32
#define AUTH_BODY_LIMIT 16384
#define AUTH_TTL 7200000u
#define AUTH_DEADLINE 15000u
#define AUTH_UNIQUE 8
enum { AUTH_NONE, AUTH_LOGIN, AUTH_REGISTER, AUTH_MAIL, AUTH_FACTOR, AUTH_RESET,
       AUTH_REFRESH, AUTH_OAUTH, AUTH_ENUM };
enum { AUTH_RESULT_OTHER, AUTH_RESULT_CREDENTIALS, AUTH_RESULT_REG_POLICY,
       AUTH_RESULT_EMAIL_CODE, AUTH_RESULT_LOGIN_OK, AUTH_RESULT_REG_OK,
       AUTH_RESULT_FACTOR };
typedef struct {
    ngx_str_t id, adapter, revision;
    u_char key[32];
    ngx_array_t *allowed, *denied;
    time_t checked, max_age;
    ngx_flag_t registration, email_verify, strict, precreate, alias_restriction;
    ngx_uint_t rate, burst, reject_limit, distinct_limit, login_limit;
    uint64_t window, ban_time, cooldown;
} auth_realm;
typedef struct auth_bucket_s {
    ngx_rbtree_node_t node;
    ngx_queue_t expiry;
    u_char key[32];
    uint64_t expires, tat, window_start, requests, failures, factor_failures, rejected, successes;
    uint64_t ban_until, cooldown_until, fence;
    ngx_uint_t active, distinct;
    u_char subjects[AUTH_UNIQUE][32];
} auth_bucket;
typedef struct {
    ngx_rbtree_node_t node;
    ngx_queue_t expiry;
    u_char id[16], subject[32];
    char realm[65], revision[97];
    uint64_t deadline, fence;
    auth_bucket *ip, *total, *combo, *account;
    ngx_uint_t flow;
    ngx_flag_t precreated, observe;
} auth_attempt;
typedef struct {
    ngx_uint_t magic;
    u_char key_tag[32];
    ngx_rbtree_t buckets, attempts;
    ngx_rbtree_node_t bucket_sentinel, attempt_sentinel;
    ngx_queue_t bucket_expiry, attempt_expiry;
    ngx_uint_t bucket_count, active;
    uint64_t admitted, rejected, banned, feedback_ok, feedback_bad, precreated, expired;
} auth_shared;
typedef struct {
    ngx_shm_zone_t *zone;
    auth_shared *shared;
    ngx_slab_pool_t *slab;
    auth_realm realms[AUTH_REALMS];
    ngx_uint_t realm_count, max_entries, max_active;
    ngx_array_t *proxies;
    u_char *weak, admin_key[32], key_tag[32];
    ngx_uint_t weak_count;
    ngx_flag_t configured, policy_loaded, admin_ready;
    ngx_str_t node_id;
} auth_main;
typedef struct { ngx_int_t realm; ngx_uint_t mode; } auth_location;
typedef struct {
    ngx_http_request_t *owner;
    auth_realm *realm;
    auth_main *main;
    u_char id[16], subject[32], body_hmac[32];
    u_char *body;
    size_t body_len;
    ngx_uint_t flow;
    ngx_flag_t capturing, ready, reserved, account_ready, finished, control, observe;
    ngx_flag_t subject_ready, weak_guess, feedback_valid;
    ngx_str_t email, username, result, client;
    scdn_sec_ip ip;
    ngx_event_t deadline;
    ngx_int_t rejection;
    time_t expires;
} auth_request;

uint64_t auth_now(void);
ngx_int_t auth_load_policy(ngx_conf_t *, auth_main *, ngx_str_t *);
ngx_int_t auth_state_init(ngx_shm_zone_t *, void *);
ngx_int_t auth_reserve(auth_request *);
ngx_int_t auth_reserve_subject(auth_request *);
void auth_release(auth_request *);
void auth_outcome(auth_request *, ngx_uint_t);
ngx_int_t auth_precreate(auth_main *, auth_realm *, const u_char *, const u_char *, ngx_flag_t);
ngx_int_t auth_unban(auth_main *, auth_realm *, scdn_sec_ip *);
void auth_sweep(auth_main *);
ngx_int_t auth_hmac(auth_realm *, const char *, const u_char *, size_t, u_char *);
ngx_int_t auth_subject(auth_realm *, ngx_str_t *, u_char *);
ngx_flag_t auth_domain(auth_realm *, ngx_str_t *);
ngx_flag_t auth_weak(auth_main *, const u_char *, size_t);
json_object *auth_json(const u_char *, size_t);
ngx_int_t auth_secret(ngx_conf_t *, ngx_str_t *, u_char *);
#endif
