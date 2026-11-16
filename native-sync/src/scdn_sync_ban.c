#include "scdn_sync_module.h"
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#define BAN_RPC_LIMIT (4 * 1024 * 1024)
typedef struct {
  ngx_str_t socket;
  ngx_thread_pool_t *threads;
} ban_bridge_conf;
typedef struct {
  ngx_http_request_t *r;
  ban_bridge_conf *conf;
  ngx_str_t node;
  const char *operation;
  u_char *input;
  size_t input_size;
  u_char *output;
  size_t output_size;
  ngx_uint_t status;
} ban_bridge_job;
static int same(ngx_str_t value, const char *text) {
  return value.len == strlen(text) && !memcmp(value.data, text, value.len);
}
static int transfer(int fd, void *data, size_t size, int writing) {
  size_t used = 0;
  while (used < size) {
    ssize_t n = writing
                    ? send(fd, (char *)data + used, size - used, MSG_NOSIGNAL)
                    : recv(fd, (char *)data + used, size - used, 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return 0;
    used += (size_t)n;
  }
  return 1;
}
static void run(void *data, ngx_log_t *log) {
  ban_bridge_job *job = data;
  struct sockaddr_un address;
  struct timeval timeout = {3, 0};
  uint32_t size, reply[2];
  int fd;
  u_char *bytes, *end;
  size_t needed = job->input_size + job->node.len + 128;
  (void)log;
  job->status = 503;
  bytes = malloc(needed);
  if (!bytes)
    return;
  end = ngx_snprintf(bytes, needed,
                     "{\"node\":\"%V\",\"operation\":\"%s\",\"body\":",
                     &job->node, job->operation);
  if (job->input_size)
    end = ngx_cpymem(end, job->input, job->input_size);
  else
    end = ngx_cpymem(end, "{}", 2);
  *end++ = '}';
  size = (uint32_t)(end - bytes);
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    free(bytes);
    return;
  }
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  ngx_memzero(&address, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, job->conf->socket.data, job->conf->socket.len);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) ||
      !transfer(fd, &size, 4, 1) || !transfer(fd, bytes, size, 1) ||
      !transfer(fd, reply, 8, 0) || reply[1] > BAN_RPC_LIMIT)
    goto finish;
  job->output = malloc(reply[1] + 1);
  if (!job->output || !transfer(fd, job->output, reply[1], 0))
    goto finish;
  job->output_size = reply[1];
  job->status = reply[0] == 200 ? 200 : reply[0] == 400 ? 400 : 503;
finish:
  close(fd);
  free(bytes);
}
static void complete(ngx_event_t *event) {
  ban_bridge_job *job = event->data;
  ngx_http_request_t *r = job->r;
  ngx_connection_t *c = r->connection;
  ngx_str_t body;
  ngx_int_t rc;
  r->main->blocked--;
  r->aio = 0;
  if (r->main->terminated) {
    free(job->output);
    c->write->handler(c->write);
    return;
  }
  body.len = job->output_size;
  body.data = ngx_pnalloc(r->pool, body.len + 1);
  if (body.data && job->output)
    memcpy(body.data, job->output, body.len);
  free(job->output);
  rc = body.data && body.len
           ? ngx_http_scdn_reply(r, job->status, &body)
           : ngx_http_scdn_error(r, 503, "ban_agent_unavailable");
  ngx_http_finalize_request(r, rc);
  ngx_http_run_posted_requests(c);
}
static void ready(ngx_http_request_t *r) {
  ban_bridge_job *job = ngx_http_get_module_ctx(r, ngx_http_scdn_sync_module);
  ngx_chain_t *chain;
  size_t n = 0;
  u_char *end;
  ngx_thread_task_t *task;
  if (r->request_body && r->request_body->temp_file)
    goto invalid;
  for (chain = r->request_body ? r->request_body->bufs : NULL; chain;
       chain = chain->next) {
    if (!ngx_buf_in_memory(chain->buf) && ngx_buf_size(chain->buf))
      goto invalid;
    n += (size_t)ngx_buf_size(chain->buf);
    if (n > 65536)
      goto invalid;
  }
  job->input_size = n;
  job->input = ngx_pnalloc(r->pool, n + 1);
  if (!job->input)
    goto invalid;
  end = job->input;
  for (chain = r->request_body ? r->request_body->bufs : NULL; chain;
       chain = chain->next)
    if (ngx_buf_size(chain->buf))
      end = ngx_cpymem(end, chain->buf->pos, (size_t)ngx_buf_size(chain->buf));
  task = ngx_thread_task_alloc(r->pool, 0);
  if (!task)
    goto invalid;
  task->ctx = job;
  task->handler = run;
  task->event.handler = complete;
  task->event.data = job;
  task->event.log = r->connection->log;
  r->main->blocked++;
  r->aio = 1;
  if (ngx_thread_task_post(job->conf->threads, task) == NGX_OK)
    return;
  r->main->blocked--;
  r->aio = 0;
invalid:
  ngx_http_finalize_request(r,
                            ngx_http_scdn_error(r, 400, "invalid_ban_request"));
}
char *scdn_sync_ban_directive(ngx_conf_t *cf, ngx_command_t *cmd,
                              void *configuration) {
  ngx_http_scdn_main_conf_t *main = configuration;
  ngx_str_t *v = cf->args->elts, name = ngx_string("scdn_sync_ban");
  ban_bridge_conf *conf;
  (void)cmd;
  if (main->ban_bridge || v[1].len > 100 || v[1].data[0] != '/')
    return "requires one absolute Ban Agent bridge socket";
  conf = ngx_pcalloc(cf->pool, sizeof(*conf));
  if (!conf)
    return NGX_CONF_ERROR;
  conf->socket = v[1];
  conf->threads = ngx_thread_pool_add(cf, &name);
  main->ban_bridge = conf;
  return conf->threads ? NGX_CONF_OK : NGX_CONF_ERROR;
}
ngx_int_t scdn_sync_ban_handler(ngx_http_request_t *r,
                                ngx_http_scdn_main_conf_t *main,
                                ngx_http_scdn_peer_t *peer,
                                ngx_flag_t exchange) {
  const char *operation = NULL;
  ban_bridge_job *job;
  ngx_int_t rc;
  if (!main->ban_bridge)
    return NGX_DECLINED;
  if (exchange) {
    if (same(r->uri, "/_scdn_sync/v1/ban/proposals"))
      operation = "proposals";
    if (same(r->uri, "/_scdn_sync/v1/ban/results"))
      operation = "results";
    if (same(r->uri, "/_scdn_sync/v1/ban/snapshot"))
      operation = "snapshot";
  } else {
    if (same(r->uri, "/__scdn_sync/v1/ban/status"))
      operation = "status";
    if (same(r->uri, "/__scdn_sync/v1/ban/unban"))
      operation = "unban";
  }
  if (!operation)
    return NGX_DECLINED;
  if (main->role != SCDN_SYNC_MASTER)
    return ngx_http_scdn_error(r, 403, "ban_master_required");
  int reading = !strcmp(operation, "snapshot") || !strcmp(operation, "status");
  if (reading ? !(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))
              : r->method != NGX_HTTP_POST)
    return ngx_http_scdn_error(r, 405, "method_not_allowed");
  if (r != r->main || r->headers_in.chunked ||
      r->headers_in.content_length_n > 65536 ||
      (reading && r->headers_in.content_length_n > 0))
    return ngx_http_scdn_error(r, 400, "invalid_ban_body");
  job = ngx_pcalloc(r->pool, sizeof(*job));
  if (!job)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  job->r = r;
  job->conf = main->ban_bridge;
  job->operation = operation;
  if (peer)
    job->node = peer->id;
  else {
    ngx_str_set(&job->node, "__control__");
  }
  ngx_http_set_ctx(r, job, ngx_http_scdn_sync_module);
  r->request_body_in_single_buf = 1;
  rc = ngx_http_read_client_request_body(r, ready);
  return rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc : NGX_DONE;
}
