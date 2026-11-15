#ifndef SCDN_API_H
#define SCDN_API_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t model, input, stream;
} scdn_api_json_t;

/* Bounded, complete JSON validation; only top-level schema signals are kept. */
ngx_flag_t scdn_api_json(const u_char *bytes, size_t length,
    scdn_api_json_t *signals);

/* Edge calls prepare before choosing its named proxy location. NGX_DONE means
 * an asynchronous body read owns the request, exactly as the mirror module. */
ngx_int_t ngx_http_scdn_api_prepare(ngx_http_request_t *r);
ngx_str_t *ngx_http_scdn_api_location(ngx_http_request_t *r,
    ngx_str_t *fallback);

extern ngx_module_t ngx_http_scdn_api_module;
#endif
