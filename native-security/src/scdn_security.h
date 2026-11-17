#ifndef SCDN_SECURITY_COMMON_H
#define SCDN_SECURITY_COMMON_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct { ngx_uint_t family; u_char bytes[16]; } scdn_sec_ip;

static ngx_inline ngx_flag_t
scdn_sec_name(ngx_str_t *name)
{
    size_t i;
    if (!name->len || name->len > 96) return 0;
    for (i = 0; i < name->len; i++) {
        u_char c = name->data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || (i && (c == '-' || c == '_')))) return 0;
    }
    return 1;
}

static ngx_inline ngx_int_t
scdn_sec_from_sockaddr(struct sockaddr *address, scdn_sec_ip *ip)
{
    ngx_memzero(ip, sizeof(*ip));
    ip->family = address->sa_family;
    if (address->sa_family == AF_INET) {
        ngx_memcpy(ip->bytes, &((struct sockaddr_in *) address)->sin_addr, 4);
        return NGX_OK;
    }
#if (NGX_HAVE_INET6)
    if (address->sa_family == AF_INET6) {
        u_char *p = ((struct sockaddr_in6 *) address)->sin6_addr.s6_addr;
        static const u_char mapped[12] = {0,0,0,0,0,0,0,0,0,0,255,255};
        if (!ngx_memcmp(p, mapped, 12)) {
            ip->family = AF_INET; ngx_memcpy(ip->bytes, p + 12, 4);
        } else ngx_memcpy(ip->bytes, p, 16);
        return NGX_OK;
    }
#endif
    return NGX_ERROR;
}

static ngx_inline void
scdn_sec_to_sockaddr(scdn_sec_ip *ip, ngx_sockaddr_t *address)
{
    ngx_memzero(address, sizeof(*address));
    address->sockaddr.sa_family = (sa_family_t) ip->family;
    if (ip->family == AF_INET) ngx_memcpy(&address->sockaddr_in.sin_addr, ip->bytes, 4);
#if (NGX_HAVE_INET6)
    else ngx_memcpy(&address->sockaddr_in6.sin6_addr, ip->bytes, 16);
#endif
}

static ngx_inline ngx_flag_t
scdn_sec_trusted(scdn_sec_ip *ip, ngx_array_t *proxies)
{
    ngx_sockaddr_t address;
    if (!proxies || !proxies->nelts) return 0;
    scdn_sec_to_sockaddr(ip, &address);
    return ngx_cidr_match(&address.sockaddr, proxies) == NGX_OK;
}

static ngx_inline ngx_int_t
scdn_sec_parse_ip(ngx_pool_t *pool, ngx_str_t text, scdn_sec_ip *ip)
{
    ngx_addr_t address;
    if (text.len > 2 && text.data[0] == '[' && text.data[text.len - 1] == ']') {
        text.data++; text.len -= 2;
    }
    if (!text.len || text.len > NGX_INET6_ADDRSTRLEN) return NGX_ERROR;
    if (ngx_parse_addr(pool, &address, text.data, text.len) != NGX_OK) return NGX_ERROR;
    return scdn_sec_from_sockaddr(address.sockaddr, ip);
}

static ngx_inline ngx_int_t
scdn_sec_cidr(ngx_str_t *text, ngx_cidr_t *cidr)
{
    if (ngx_ptocidr(text, cidr) != NGX_OK) return NGX_ERROR;
#if (NGX_HAVE_INET6)
    if (cidr->family == AF_INET6) {
        static const u_char mapped[12] = {0,0,0,0,0,0,0,0,0,0,255,255};
        u_char *p = cidr->u.in6.addr.s6_addr, *m = cidr->u.in6.mask.s6_addr;
        ngx_uint_t i;
        if (!ngx_memcmp(p, mapped, 12)) {
            in_addr_t address, mask;
            for (i = 0; i < 12; i++) if (m[i] != 255) return NGX_ERROR;
            ngx_memcpy(&address, p + 12, 4); ngx_memcpy(&mask, m + 12, 4);
            cidr->family = AF_INET; cidr->u.in.addr = address; cidr->u.in.mask = mask;
        }
    }
#endif
    return NGX_OK;
}

static ngx_inline ngx_int_t
scdn_sec_add_proxy(ngx_conf_t *cf, ngx_array_t **proxies, ngx_str_t *text)
{
    ngx_cidr_t cidr, *entry;
    if (scdn_sec_cidr(text, &cidr) != NGX_OK) return NGX_ERROR;
    if (!*proxies) *proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
    if (!*proxies || (*proxies)->nelts >= 1024) return NGX_ERROR;
    entry = ngx_array_push(*proxies);
    if (!entry) return NGX_ERROR;
    *entry = cidr;
    return NGX_OK;
}

static ngx_inline ngx_int_t
scdn_sec_client(ngx_http_request_t *r, ngx_array_t *proxies,
    scdn_sec_ip *peer, scdn_sec_ip *client, ngx_flag_t *forwarded)
{
    ngx_sockaddr_t address;
    socklen_t length = sizeof(address);
    struct sockaddr *source = &address.sockaddr;
    ngx_list_part_t *part;
    ngx_table_elt_t *headers, *xff = NULL;
    ngx_uint_t i, hops = 0;
    size_t start, end;
    ngx_str_t text;
    *forwarded = 0;
    if (getpeername(r->connection->fd, source, &length)) {
#if (NGX_HTTP_REALIP)
        {
            ngx_uint_t module_index;
            ngx_flag_t realip_loaded = 0;
            ngx_str_t variable = ngx_string("realip_remote_addr");
            ngx_http_variable_value_t *original;
            ngx_str_t text;
            for (module_index = 0; r->main_conf && ngx_cycle->modules[module_index]; module_index++) {
                if (ngx_cycle->modules[module_index]->name && !ngx_strcmp(
                    ngx_cycle->modules[module_index]->name, "ngx_http_realip_module")) realip_loaded = 1;
            }
            if (realip_loaded) {
                original = ngx_http_get_variable(r, &variable, ngx_hash_key(variable.data, variable.len));
                if (!original || original->not_found) return NGX_ERROR;
                text.data = original->data; text.len = original->len;
                if (scdn_sec_parse_ip(r->pool, text, peer) != NGX_OK) return NGX_ERROR;
                goto peer_ready;
            }
            source = r->connection->sockaddr;
        }
#else
        source = r->connection->sockaddr;
#endif
    }
    if (!source || scdn_sec_from_sockaddr(source, peer) != NGX_OK) return NGX_ERROR;
#if (NGX_HTTP_REALIP)
peer_ready:
#endif
    *client = *peer;
    if (!scdn_sec_trusted(peer, proxies)) return NGX_OK;
    part = &r->headers_in.headers.part; headers = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (!part->next) break;
            part = part->next; headers = part->elts; i = 0;
        }
        if (headers[i].hash && headers[i].key.len == 15
            && !ngx_strncasecmp(headers[i].key.data, (u_char *) "X-Forwarded-For", 15)) {
            if (xff) return NGX_ERROR;
            xff = &headers[i];
        }
    }
    if (!xff) return NGX_OK;
    if (!xff->value.len || xff->value.len > 2048) return NGX_ERROR;
    end = xff->value.len;
    while (end && scdn_sec_trusted(client, proxies)) {
        if (++hops > 16) return NGX_ERROR;
        start = end;
        while (start && xff->value.data[start - 1] != ',') start--;
        text.data = xff->value.data + start; text.len = end - start;
        while (text.len && (*text.data == ' ' || *text.data == '\t')) { text.data++; text.len--; }
        while (text.len && (text.data[text.len - 1] == ' ' || text.data[text.len - 1] == '\t')) text.len--;
        if (scdn_sec_parse_ip(r->pool, text, client) != NGX_OK) return NGX_ERROR;
        *forwarded = 1;
        if (!start) break;
        end = start - 1;
        if (!end) return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_inline ngx_str_t
scdn_sec_text(ngx_pool_t *pool, scdn_sec_ip *ip)
{
    ngx_sockaddr_t address;
    ngx_str_t result = ngx_null_string;
    scdn_sec_to_sockaddr(ip, &address);
    result.data = ngx_pnalloc(pool, NGX_INET6_ADDRSTRLEN);
    if (result.data) result.len = ngx_sock_ntop(&address.sockaddr,
        ip->family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
        result.data, NGX_INET6_ADDRSTRLEN, 0);
    return result;
}
#endif
