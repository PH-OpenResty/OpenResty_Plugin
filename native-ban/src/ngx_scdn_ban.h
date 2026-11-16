#ifndef NGX_SCDN_BAN_H
#define NGX_SCDN_BAN_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
ngx_int_t ngx_http_scdn_ban_precheck(ngx_http_request_t *r);
ngx_int_t ngx_http_scdn_ban_report(ngx_http_request_t *r, ngx_uint_t source,
                                   ngx_str_t *reason);
#endif
