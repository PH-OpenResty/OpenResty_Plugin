#include "scdn_log_sync.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
extern ngx_module_t ngx_http_scdn_log_sync_module;

typedef struct {
  ngx_str_t file;
  ngx_msec_t interval;
} log_main_t;
static void *log_service;
static void *log_main(ngx_conf_t *cf) {
  log_main_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
  if (conf != NULL)
    conf->interval = NGX_CONF_UNSET_MSEC;
  return conf;
}
static ngx_int_t log_status(ngx_http_request_t *r) {
  scdn_log_sync_status status;
  u_char *data, *last;
  ngx_buf_t *buffer;
  ngx_chain_t chain;
  ngx_int_t rc;
  if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
    return NGX_HTTP_NOT_ALLOWED;
  rc = ngx_http_discard_request_body(r);
  if (rc != NGX_OK)
    return rc;
  scdn_log_sync_status_read(log_service, &status);
  data = ngx_pnalloc(r->pool, 1024);
  if (data == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  last = ngx_snprintf(
      data, 1024,
      "{\"worker_pid\":%P,\"running\":%d,\"confirmed\":%uL,\"pending\":%uL,"
      "\"files\":%uL,\"sent_requests\":%uL,\"cycles\":%uL,\"failures\":%uL,"
      "\"sample_failures\":%uL,\"error\":\"%s\",\"scope\":\"this_worker\"}\n",
      ngx_pid, status.running, status.confirmed, status.pending, status.files,
      status.sent_requests, status.cycles, status.failures,
      status.sample_failures, scdn_log_sync_error(status.error));
  r->headers_out.status = NGX_HTTP_OK;
  r->headers_out.content_length_n = last - data;
  ngx_str_set(&r->headers_out.content_type, "application/json");
  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    return rc;
  buffer = ngx_calloc_buf(r->pool);
  if (buffer == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  buffer->pos = data;
  buffer->last = last;
  buffer->memory = 1;
  buffer->last_buf = r == r->main;
  chain.buf = buffer;
  chain.next = NULL;
  return ngx_http_output_filter(r, &chain);
}
static char *log_status_directive(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *data) {
  ngx_http_core_loc_conf_t *core =
      ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  (void)cmd;
  (void)data;
  core->handler = log_status;
  return NGX_CONF_OK;
}
static ngx_command_t log_commands[] = {
    {ngx_string("scdn_log_sync_config"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(log_main_t, file), NULL},
    {ngx_string("scdn_log_sync_interval"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot, NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(log_main_t, interval), NULL},
    {ngx_string("scdn_log_sync_status"), NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     log_status_directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    ngx_null_command};
static ngx_int_t log_configure(ngx_conf_t *cf) {
  log_main_t *conf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_log_sync_module);
  if (conf->interval == NGX_CONF_UNSET_MSEC)
    conf->interval = 250;
  if (conf->interval < 10 || conf->interval > 60000) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "scdn_log_sync_interval must be 10ms to 60s");
    return NGX_ERROR;
  }
  return NGX_OK;
}
static ngx_int_t log_process(ngx_cycle_t *cycle) {
  log_main_t *conf;
  if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
    return NGX_OK;
  conf =
      ngx_http_cycle_get_module_main_conf(cycle, ngx_http_scdn_log_sync_module);
  if (conf == NULL || conf->file.len == 0)
    return NGX_OK;
  log_service =
      scdn_log_sync_start((char *)conf->file.data, (unsigned)conf->interval);
  if (log_service == NULL)
    return NGX_ERROR;
  return NGX_OK;
}
static void log_exit(ngx_cycle_t *cycle) {
  (void)cycle;
  scdn_log_sync_stop(log_service);
  log_service = NULL;
}
static ngx_http_module_t log_context = {NULL, log_configure, log_main, NULL,
                                        NULL, NULL,          NULL,     NULL};
ngx_module_t ngx_http_scdn_log_sync_module = {
    NGX_MODULE_V1, &log_context, log_commands, NGX_HTTP_MODULE,
    NULL,          NULL,         log_process,  NULL,
    NULL,          log_exit,     NULL,         NGX_MODULE_V1_PADDING};
