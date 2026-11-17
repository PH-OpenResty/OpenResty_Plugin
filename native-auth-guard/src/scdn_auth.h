#ifndef SCDN_AUTH_GUARD_H
#define SCDN_AUTH_GUARD_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
ngx_int_t ngx_http_scdn_auth_prepare(ngx_http_request_t *r);
extern ngx_module_t ngx_http_scdn_auth_guard_module;
#endif
