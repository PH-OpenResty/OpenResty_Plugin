#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "scdn_sync_module.h"

#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif

#define SCDN_API_OFF       0
#define SCDN_API_CONTROL   1
#define SCDN_API_EXCHANGE  2

typedef struct {
    ngx_uint_t mode;
} ngx_http_scdn_loc_conf_t;

static void *ngx_http_scdn_create_main(ngx_conf_t *cf);
static void *ngx_http_scdn_create_location(ngx_conf_t *cf);
static char *ngx_http_scdn_merge_location(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_scdn_role(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_scdn_peer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_scdn_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_scdn_configure(ngx_conf_t *cf);
static ngx_int_t ngx_http_scdn_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_scdn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_scdn_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_scdn_process(ngx_cycle_t *cycle);

static ngx_command_t ngx_http_scdn_commands[] = {
    { ngx_string("scdn_sync_role"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_scdn_role, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_id"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_scdn_main_conf_t, id), NULL },
    { ngx_string("scdn_sync_scope"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_scdn_main_conf_t, scope), NULL },
    { ngx_string("scdn_sync_control_token_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_scdn_main_conf_t, token_file), NULL },
    { ngx_string("scdn_sync_peer"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_scdn_peer, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_api"), NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_scdn_api, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_tasks"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_master"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_mtls"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_purge"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_site"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_local_ca"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_poll"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_cache_allow_all"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_tasks_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_state"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_source"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_peer_key"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_signing_key"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_trust_key"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_decryption_key"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_master"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_mtls"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_status_socket"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_probe"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("scdn_sync_config_allow_empty"), NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      scdn_sync_distribution_directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_scdn_context = {
    ngx_http_scdn_variables,
    ngx_http_scdn_configure,
    ngx_http_scdn_create_main,
    NULL,
    NULL,
    NULL,
    ngx_http_scdn_create_location,
    ngx_http_scdn_merge_location
};

ngx_module_t ngx_http_scdn_sync_module = {
    NGX_MODULE_V1,
    &ngx_http_scdn_context,
    ngx_http_scdn_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, ngx_http_scdn_process, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_scdn_process(ngx_cycle_t *cycle)
{
    if (scdn_sync_tasks_process(cycle) != NGX_OK) return NGX_ERROR;
    return scdn_sync_distribution_process(cycle);
}

static void *
ngx_http_scdn_create_main(ngx_conf_t *cf)
{
    ngx_http_scdn_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }
    if (ngx_array_init(&conf->peers, cf->pool, 4,
                       sizeof(ngx_http_scdn_peer_t)) != NGX_OK
        || ngx_array_init(&conf->endpoints, cf->pool, 4,
                          sizeof(ngx_http_scdn_endpoint_t)) != NGX_OK)
    {
        return NULL;
    }
    return conf;
}

static void *
ngx_http_scdn_create_location(ngx_conf_t *cf)
{
    ngx_http_scdn_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf != NULL) {
        conf->mode = NGX_CONF_UNSET_UINT;
    }
    return conf;
}

static char *
ngx_http_scdn_merge_location(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_scdn_loc_conf_t *previous = parent;
    ngx_http_scdn_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->mode, previous->mode, SCDN_API_OFF);
    return NGX_CONF_OK;
}

static char *
ngx_http_scdn_role(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_http_scdn_main_conf_t *conf = configuration;
    ngx_str_t *value = cf->args->elts;

    if (conf->role_set) {
        return "is duplicate";
    }
    conf->role = scdn_sync_parse_role(value[1].data, value[1].len);
    if (conf->role == SCDN_SYNC_INVALID) {
        return "must be off, master or node";
    }
    conf->role_set = 1;
    return NGX_CONF_OK;
}

static char *
ngx_http_scdn_peer(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_http_scdn_main_conf_t *conf = configuration;
    ngx_http_scdn_peer_t *peer, *peers;
    ngx_str_t *value = cf->args->elts;
    u_char fingerprint[32];
    ngx_uint_t i;

    if (!scdn_sync_valid_id(value[1].data, value[1].len)
        || !scdn_sync_valid_id(value[2].data, value[2].len)
        || !scdn_sync_decode_fingerprint(value[3].data, value[3].len,
                                         fingerprint))
    {
        return "requires valid node/scope IDs and a lowercase SHA-256 DER fingerprint";
    }
    if (conf->peers.nelts >= SCDN_SYNC_MAX_PEERS) {
        return "exceeds the peer limit";
    }
    peers = conf->peers.elts;
    for (i = 0; i < conf->peers.nelts; i++) {
        if ((peers[i].id.len == value[1].len
             && ngx_memcmp(peers[i].id.data, value[1].data, value[1].len) == 0)
            || scdn_sync_secure_equal(peers[i].fingerprint, 32,
                                      fingerprint, 32))
        {
            return "duplicates a node ID or certificate fingerprint";
        }
    }
    peer = ngx_array_push(&conf->peers);
    if (peer == NULL) {
        return NGX_CONF_ERROR;
    }
    peer->id = value[1];
    peer->scope = value[2];
    ngx_memcpy(peer->fingerprint, fingerprint, 32);
    return NGX_CONF_OK;
}

static char *
ngx_http_scdn_api(ngx_conf_t *cf, ngx_command_t *cmd, void *configuration)
{
    ngx_http_scdn_loc_conf_t *conf = configuration;
    ngx_http_scdn_main_conf_t *main;
    ngx_http_core_loc_conf_t *location;
    ngx_http_scdn_endpoint_t *endpoint;
    ngx_str_t *value = cf->args->elts;

    if (conf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }
    if (ngx_strcmp(value[1].data, "control") == 0) {
        conf->mode = SCDN_API_CONTROL;
    } else if (ngx_strcmp(value[1].data, "exchange") == 0) {
        conf->mode = SCDN_API_EXCHANGE;
    } else {
        return "must be control or exchange";
    }
    location = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (location->handler != NULL) {
        return "conflicts with another content handler";
    }
    location->handler = ngx_http_scdn_handler;
    main = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_sync_module);
    endpoint = ngx_array_push(&main->endpoints);
    if (endpoint == NULL) {
        return NGX_CONF_ERROR;
    }
    endpoint->context = cf->ctx;
    endpoint->mode = conf->mode;
    return NGX_CONF_OK;
}

static void
ngx_http_scdn_clear_token(void *data)
{
    ngx_str_t *token = data;

    scdn_sync_clear(token->data, token->len);
}

ngx_int_t
scdn_sync_load_token(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *token)
{
    int fd, flags;
    ssize_t count;
    size_t length, total = 0;
    u_char bytes[SCDN_SYNC_TOKEN_MAX + 3];
    struct stat info;
    ngx_pool_cleanup_t *cleanup;

    if (path->len == 0 || path->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "scdn_sync control requires an absolute token file");
        return NGX_ERROR;
    }
    flags = O_RDONLY|O_NONBLOCK;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open((char *) path->data, flags);
    if (fd == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                          "scdn_sync cannot open the control token file");
        return NGX_ERROR;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
        || (info.st_mode & 077) != 0 || info.st_size < SCDN_SYNC_TOKEN_MIN
        || info.st_size > SCDN_SYNC_TOKEN_MAX + 2)
    {
        close(fd);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "scdn_sync token must be a private regular file with a bounded token");
        return NGX_ERROR;
    }
    while (total < sizeof(bytes)) {
        count = read(fd, bytes + total, sizeof(bytes) - total);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            close(fd);
            scdn_sync_clear(bytes, sizeof(bytes));
            return NGX_ERROR;
        }
        if (count == 0) {
            break;
        }
        total += (size_t) count;
    }
    close(fd);
    length = total;
    if (length != 0 && bytes[length - 1] == '\n') {
        length--;
        if (length != 0 && bytes[length - 1] == '\r') {
            length--;
        }
    }
    if (!scdn_sync_valid_token(bytes, length)) {
        scdn_sync_clear(bytes, sizeof(bytes));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "scdn_sync token must contain 43 to 128 base64url characters");
        return NGX_ERROR;
    }
    token->data = ngx_pnalloc(cf->pool, length);
    cleanup = ngx_pool_cleanup_add(cf->pool, 0);
    if (token->data == NULL || cleanup == NULL) {
        scdn_sync_clear(bytes, sizeof(bytes));
        return NGX_ERROR;
    }
    token->len = length;
    ngx_memcpy(token->data, bytes, length);
    scdn_sync_clear(bytes, sizeof(bytes));
    cleanup->data = token;
    cleanup->handler = ngx_http_scdn_clear_token;
    return NGX_OK;
}

static ngx_int_t
ngx_http_scdn_configure(ngx_conf_t *cf)
{
    ngx_http_scdn_main_conf_t *conf;
    ngx_http_scdn_endpoint_t *endpoints;
    ngx_http_core_loc_conf_t *location;
    ngx_uint_t i;
    ngx_flag_t control = 0;
#if (NGX_HTTP_SSL)
    ngx_http_ssl_srv_conf_t *ssl;
#endif

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_sync_module);
    if (scdn_sync_tasks_configure(cf, conf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (scdn_sync_distribution_configure(cf, conf) != NGX_OK) return NGX_ERROR;
    if (conf->role == SCDN_SYNC_OFF) {
        if (conf->endpoints.nelts != 0 || conf->peers.nelts != 0
            || conf->id.data != NULL || conf->scope.data != NULL
            || conf->token_file.data != NULL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "scdn_sync directives require an active role");
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    if (!scdn_sync_valid_id(conf->id.data, conf->id.len)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "scdn_sync requires a valid instance ID");
        return NGX_ERROR;
    }
    if (conf->role == SCDN_SYNC_NODE) {
        if (!scdn_sync_valid_id(conf->scope.data, conf->scope.len)
            || conf->peers.nelts != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "scdn_sync node requires a scope and cannot register peers");
            return NGX_ERROR;
        }
    } else if (conf->scope.data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "scdn_sync master scopes belong to individual peer registrations");
        return NGX_ERROR;
    }
    if (conf->scope.data == NULL) {
        ngx_str_set(&conf->scope, "");
    }
    endpoints = conf->endpoints.elts;
    for (i = 0; i < conf->endpoints.nelts; i++) {
        location = endpoints[i].context->loc_conf[ngx_http_core_module.ctx_index];
        if (location->handler != ngx_http_scdn_handler) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "scdn_sync API was replaced by another content handler");
            return NGX_ERROR;
        }
        if (endpoints[i].mode == SCDN_API_CONTROL) {
            control = 1;
            continue;
        }
        if (conf->role != SCDN_SYNC_MASTER) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "scdn_sync exchange API requires the master role");
            return NGX_ERROR;
        }
#if (NGX_HTTP_SSL)
        ssl = endpoints[i].context->srv_conf[ngx_http_ssl_module.ctx_index];
        if (ssl->verify != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "scdn_sync exchange requires ssl_verify_client on");
            return NGX_ERROR;
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "scdn_sync exchange requires HTTP SSL support");
        return NGX_ERROR;
#endif
    }
    if (control) {
        return scdn_sync_load_token(cf, &conf->token_file, &conf->token);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_scdn_variables(ngx_conf_t *cf)
{
    static ngx_str_t names[] = {
        ngx_string("scdn_sync_role"), ngx_string("scdn_sync_id"),
        ngx_string("scdn_sync_scope")
    };
    ngx_http_variable_t *variable;
    ngx_uint_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        variable = ngx_http_add_variable(cf, &names[i], 0);
        if (variable == NULL) {
            return NGX_ERROR;
        }
        variable->get_handler = ngx_http_scdn_variable;
        variable->data = i;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_scdn_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_scdn_main_conf_t *conf;
    ngx_str_t value;

    conf = ngx_http_get_module_main_conf(r, ngx_http_scdn_sync_module);
    if (data == 0) {
        value.data = (u_char *) scdn_sync_role_name(conf->role);
        value.len = ngx_strlen(value.data);
    } else {
        value = data == 1 ? conf->id : conf->scope;
    }
    if (value.data == NULL) {
        ngx_str_set(&value, "");
    }
    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

ngx_int_t
ngx_http_scdn_header(ngx_http_request_t *r, const char *key, const char *value)
{
    ngx_table_elt_t *header;

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }
    header->hash = 1;
    header->key.data = (u_char *) key;
    header->key.len = ngx_strlen(key);
    header->value.data = (u_char *) value;
    header->value.len = ngx_strlen(value);
    return NGX_OK;
}

ngx_int_t
ngx_http_scdn_reply(ngx_http_request_t *r, ngx_uint_t status, ngx_str_t *body)
{
    ngx_buf_t *buffer;
    ngx_chain_t chain;
    ngx_int_t rc;

    if (ngx_http_scdn_header(r, "Cache-Control", "no-store") != NGX_OK
        || ngx_http_scdn_header(r, "X-Content-Type-Options", "nosniff") != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buffer = ngx_calloc_buf(r->pool);
    if (buffer == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buffer->pos = body->data;
    buffer->last = body->data + body->len;
    buffer->memory = body->len != 0;
    buffer->last_buf = (r == r->main);
    buffer->last_in_chain = 1;
    chain.buf = buffer;
    chain.next = NULL;
    r->headers_out.status = status;
    r->headers_out.content_length_n = body->len;
    if (r->headers_out.content_type.len == 0) {
        ngx_str_set(&r->headers_out.content_type, "application/json");
    }
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &chain);
}

ngx_int_t
ngx_http_scdn_error(ngx_http_request_t *r, ngx_uint_t status, const char *code)
{
    ngx_str_t body;
    u_char *end;

    body.data = ngx_pnalloc(r->pool, 192);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    end = ngx_snprintf(body.data, 192, "{\"ok\":false,\"error\":\"%s\"}\n", code);
    body.len = end - body.data;
    return ngx_http_scdn_reply(r, status, &body);
}

static ngx_flag_t
ngx_http_scdn_local_transport(ngx_http_request_t *r)
{
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);

    /* Read the transport peer, not an address rewritten by real_ip headers. */
    if (getpeername(r->connection->fd, (struct sockaddr *) &address,
                    &length) != 0)
    {
        return 0;
    }
    if (address.ss_family == AF_UNIX) {
        return 1;
    }
    if (address.ss_family == AF_INET) {
        return (ntohl(((struct sockaddr_in *) &address)->sin_addr.s_addr)
                >> 24) == 127;
    }
#if (NGX_HAVE_INET6)
    if (address.ss_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(
            &((struct sockaddr_in6 *) &address)->sin6_addr);
    }
#endif
    return 0;
}

static ngx_http_scdn_peer_t *
ngx_http_scdn_authenticate_peer(ngx_http_request_t *r,
    ngx_http_scdn_main_conf_t *conf)
{
#if (NGX_HTTP_SSL)
    X509 *certificate;
    u_char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int length;
    ngx_http_scdn_peer_t *peers;
    ngx_uint_t i;

    if (r->connection->ssl == NULL
        || SSL_get_verify_result(r->connection->ssl->connection) != X509_V_OK)
    {
        return NULL;
    }
    certificate = SSL_get_peer_certificate(r->connection->ssl->connection);
    if (certificate == NULL) {
        return NULL;
    }
    if (X509_digest(certificate, EVP_sha256(), fingerprint, &length) != 1
        || length != 32)
    {
        X509_free(certificate);
        return NULL;
    }
    X509_free(certificate);
    peers = conf->peers.elts;
    for (i = 0; i < conf->peers.nelts; i++) {
        if (scdn_sync_secure_equal(peers[i].fingerprint, 32,
                                   fingerprint, length))
        {
            return &peers[i];
        }
    }
#endif
    return NULL;
}

static ngx_flag_t
ngx_http_scdn_path(ngx_http_request_t *r, const char *value)
{
    size_t length = ngx_strlen(value);

    return r->uri.len == length && ngx_memcmp(r->uri.data, value, length) == 0;
}

static ngx_int_t
ngx_http_scdn_capabilities(ngx_http_request_t *r,
    ngx_http_scdn_main_conf_t *conf, ngx_http_scdn_peer_t *peer)
{
    ngx_str_t body;
    u_char *end;

    body.data = ngx_pnalloc(r->pool, 1536);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    end = ngx_snprintf(body.data, 1536,
        "{\"ok\":true,\"implementation\":\"native\",\"version\":\""
        SCDN_SYNC_NATIVE_VERSION "\",\"protocol\":\"" SCDN_SYNC_PROTOCOL
        "\",\"role\":\"%s\",\"instance_id\":\"%V\","
        "\"features\":{\"role_isolation\":true,\"authenticated_control\":true,"
        "\"mtls_peer_registry\":%s,\"encrypted_distribution\":%s,"
        "\"node_pull\":%s,\"apply_transactions\":%s,"
        "\"business_health\":%s,\"cache_tasks\":%s,"
        "\"cache_refresh\":%s,\"cache_preheat\":%s}",
        scdn_sync_role_name(conf->role), &conf->id,
        conf->role == SCDN_SYNC_MASTER ? "true" : "false",
        conf->distribution ? "true" : "false",
        conf->distribution && conf->role == SCDN_SYNC_NODE ? "true" : "false",
        conf->distribution && conf->role == SCDN_SYNC_NODE ? "true" : "false",
        scdn_sync_distribution_health(conf) ? "true" : "false",
        conf->cache.directory.len ? "true" : "false",
        conf->cache.directory.len ? "true" : "false",
        conf->cache.directory.len ? "true" : "false");
    if (peer != NULL) {
        end = ngx_snprintf(end, body.data + 1536 - end,
            ",\"peer\":{\"node_id\":\"%V\",\"scope_id\":\"%V\"}",
            &peer->id, &peer->scope);
    }
    end = ngx_cpymem(end, "}\n", 2);
    body.len = end - body.data;
    return ngx_http_scdn_reply(r, NGX_HTTP_OK, &body);
}

static ngx_int_t
ngx_http_scdn_status(ngx_http_request_t *r, ngx_http_scdn_main_conf_t *conf)
{
    ngx_str_t body;
    u_char *end;

    body.data = ngx_pnalloc(r->pool, 1024);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    end = ngx_snprintf(body.data, 1024,
        "{\"ok\":true,\"version\":\"" SCDN_SYNC_NATIVE_VERSION
        "\",\"role\":\"%s\",\"instance_id\":\"%V\","
        "\"scope_id\":\"%V\",\"configured_peers\":%ui,"
        "\"sync_state\":\"not_started\",\"applied_revision\":null,"
        "\"business_health\":\"unknown\",\"worker_pid\":%P}\n",
        scdn_sync_role_name(conf->role), &conf->id, &conf->scope,
        conf->peers.nelts, ngx_pid);
    body.len = end - body.data;
    return ngx_http_scdn_reply(r, NGX_HTTP_OK, &body);
}

static ngx_int_t
ngx_http_scdn_peers(ngx_http_request_t *r, ngx_http_scdn_main_conf_t *conf)
{
    ngx_http_scdn_peer_t *peers = conf->peers.elts;
    ngx_str_t body;
    size_t size;
    u_char *end;
    ngx_uint_t i;

    size = 64 + conf->peers.nelts * (2 * SCDN_SYNC_MAX_ID + 64);
    body.data = ngx_pnalloc(r->pool, size);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    end = ngx_cpymem(body.data, "{\"ok\":true,\"peers\":[", 20);
    for (i = 0; i < conf->peers.nelts; i++) {
        end = ngx_snprintf(end, body.data + size - end,
            "%s{\"node_id\":\"%V\",\"scope_id\":\"%V\"}",
            i == 0 ? "" : ",", &peers[i].id, &peers[i].scope);
    }
    end = ngx_cpymem(end, "]}\n", 3);
    body.len = end - body.data;
    return ngx_http_scdn_reply(r, NGX_HTTP_OK, &body);
}

static ngx_int_t
ngx_http_scdn_handler(ngx_http_request_t *r)
{
    ngx_http_scdn_main_conf_t *conf;
    ngx_http_scdn_loc_conf_t *location;
    ngx_http_scdn_peer_t *peer;
    ngx_table_elt_t *authorization;
    ngx_str_t *credential;
    ngx_int_t rc;

    conf = ngx_http_get_module_main_conf(r, ngx_http_scdn_sync_module);
    location = ngx_http_get_module_loc_conf(r, ngx_http_scdn_sync_module);
    if (conf->role == SCDN_SYNC_OFF || location->mode == SCDN_API_OFF) {
        return ngx_http_scdn_error(r, NGX_HTTP_NOT_FOUND, "route_not_found");
    }
    if (r->unparsed_uri.len != r->uri.len
        || ngx_memcmp(r->unparsed_uri.data, r->uri.data, r->uri.len) != 0)
    {
        r->keepalive = 0;
        return ngx_http_scdn_error(r, NGX_HTTP_BAD_REQUEST, "invalid_request_target");
    }
    peer = NULL;
    if (location->mode == SCDN_API_CONTROL) {
        if (!ngx_http_scdn_local_transport(r)) {
            return ngx_http_scdn_error(r, NGX_HTTP_FORBIDDEN, "local_transport_required");
        }
        authorization = r->headers_in.authorization;
        if (authorization == NULL) {
            if (ngx_http_scdn_header(r, "WWW-Authenticate",
                                    "Bearer realm=\"scdn-sync\"") != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            return ngx_http_scdn_error(r, NGX_HTTP_UNAUTHORIZED, "control_unauthorized");
        }
        credential = &authorization->value;
        if (credential->len < 7
            || ngx_strncasecmp(credential->data, (u_char *) "Bearer ", 7) != 0
            || !scdn_sync_secure_equal(credential->data + 7, credential->len - 7,
                                       conf->token.data, conf->token.len))
        {
            if (ngx_http_scdn_header(r, "WWW-Authenticate",
                                    "Bearer realm=\"scdn-sync\"") != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            return ngx_http_scdn_error(r, NGX_HTTP_UNAUTHORIZED, "control_unauthorized");
        }
    } else {
        peer = ngx_http_scdn_authenticate_peer(r, conf);
        if (peer == NULL) {
            return ngx_http_scdn_error(r, NGX_HTTP_FORBIDDEN, "node_forbidden");
        }
    }
    rc = scdn_sync_distribution_handler(r, conf, peer, location->mode == SCDN_API_EXCHANGE);
    if (rc != NGX_DECLINED) return rc;
    rc = scdn_sync_tasks_handler(r, conf, peer,
                                location->mode == SCDN_API_EXCHANGE);
    if (rc != NGX_DECLINED) {
        return rc;
    }
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        r->keepalive = 0;
        if (ngx_http_scdn_header(r, "Allow", "GET, HEAD") != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return ngx_http_scdn_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->keepalive = 0;
        return ngx_http_scdn_error(r, NGX_HTTP_BAD_REQUEST, "request_body_not_allowed");
    }
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    if (location->mode == SCDN_API_EXCHANGE) {
        if (ngx_http_scdn_path(r, "/_scdn_sync/v1/capabilities")) {
            return ngx_http_scdn_capabilities(r, conf, peer);
        }
    } else {
        if (ngx_http_scdn_path(r, "/__scdn_sync/v1/status")) {
            return ngx_http_scdn_status(r, conf);
        }
        if (ngx_http_scdn_path(r, "/__scdn_sync/v1/capabilities")) {
            return ngx_http_scdn_capabilities(r, conf, NULL);
        }
        if (conf->role == SCDN_SYNC_MASTER
            && ngx_http_scdn_path(r, "/__scdn_sync/v1/peers"))
        {
            return ngx_http_scdn_peers(r, conf);
        }
    }
    return ngx_http_scdn_error(r, NGX_HTTP_NOT_FOUND, "route_not_found");
}
