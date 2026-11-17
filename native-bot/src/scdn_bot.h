#ifndef SCDN_BOT_H
#define SCDN_BOT_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
ngx_int_t ngx_http_scdn_bot_check(ngx_http_request_t *r);
extern ngx_module_t ngx_http_scdn_bot_module;
#endif
