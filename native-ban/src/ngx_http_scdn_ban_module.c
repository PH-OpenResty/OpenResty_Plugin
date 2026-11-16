#include "ban_common.h"
#include "ngx_scdn_ban.h"
#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define QUEUE 1024
typedef struct {
  ngx_str_t socket;
  ngx_uint_t uid;
  uint8_t instance[16], boot[16];
} ban_main;
typedef struct {
  ngx_flag_t enabled;
  ngx_http_complex_value_t scope;
  ngx_uint_t deny;
  ngx_str_t reason;
} ban_location;
typedef struct {
  ngx_http_request_t *owner;
  ban_address ip;
  ngx_str_t scope, reason;
  uint8_t request[16];
  ngx_uint_t reported;
  ngx_flag_t checked;
  ngx_int_t result;
} ban_request;
static ban_main *main_conf;
static ban_event queue[QUEUE];
static unsigned first, count;
static uint64_t sequence;
static uint8_t producer[16];
static int agent = -1, awaiting = 0;
static ban_view *view;
static ngx_event_t timer;
extern ngx_module_t ngx_http_scdn_ban_module;
static char *directive(ngx_conf_t *, ngx_command_t *, void *);
static void *create_main(ngx_conf_t *);
static void *create_location(ngx_conf_t *);
static char *merge_location(ngx_conf_t *, void *, void *);
static ngx_int_t preconfiguration(ngx_conf_t *);
static ngx_int_t postconfiguration(ngx_conf_t *);
static ngx_int_t worker_init(ngx_cycle_t *);
static void worker_exit(ngx_cycle_t *);
static ngx_int_t deny_handler(ngx_http_request_t *);
static void tick(ngx_event_t *);
static void setter(ngx_http_request_t *, ngx_http_variable_value_t *,
                   uintptr_t);
static ngx_command_t commands[] = {
    {ngx_string("scdn_ban_agent"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3,
     directive, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},
    {ngx_string("scdn_ban"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ban_location, enabled), NULL},
    {ngx_string("scdn_ban_scope"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     directive, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    {ngx_string("scdn_ban_deny"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, directive,
     NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    ngx_null_command};
static ngx_http_module_t context = {
    preconfiguration, postconfiguration, create_main, NULL, NULL, NULL,
    create_location,  merge_location};
ngx_module_t ngx_http_scdn_ban_module = {
    NGX_MODULE_V1, &context,    commands,    NGX_HTTP_MODULE,
    NULL,          NULL,        worker_init, NULL,
    NULL,          worker_exit, NULL,        NGX_MODULE_V1_PADDING};
static int text_equal(ngx_str_t *v, const char *s) {
  return v->len == strlen(s) && !memcmp(v->data, s, v->len);
}
static int valid_name(ngx_str_t *v, int reason) {
  size_t i;
  if (!v->len || v->len >= (reason ? 64 : 96))
    return 0;
  for (i = 0; i < v->len; i++) {
    u_char c = v->data[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_' ||
          (reason && (c == '.' || c == ':'))))
      return 0;
  }
  return 1;
}
static void *create_main(ngx_conf_t *cf) {
  return ngx_pcalloc(cf->pool, sizeof(ban_main));
}
static void *create_location(ngx_conf_t *cf) {
  ban_location *c = ngx_pcalloc(cf->pool, sizeof(*c));
  if (c)
    c->enabled = NGX_CONF_UNSET;
  return c;
}
static char *merge_location(ngx_conf_t *cf, void *parent, void *child) {
  ban_location *p = parent, *c = child;
  ban_main *m =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_scdn_ban_module);
  ngx_conf_merge_value(c->enabled, p->enabled, 0);
  if (!c->scope.value.len)
    c->scope = p->scope;
  if (c->enabled && (!m->socket.len || !c->scope.value.len))
    return "requires agent and explicit stable site scope";
  return NGX_CONF_OK;
}
static char *directive(ngx_conf_t *cf, ngx_command_t *cmd,
                       void *configuration) {
  ngx_str_t *v = cf->args->elts;
  ban_location *c = configuration;
  if (text_equal(&cmd->name, "scdn_ban_agent")) {
    ban_main *m = configuration;
    ngx_int_t uid = ngx_atoi(v[2].data, v[2].len);
    if (m->socket.len || v[1].len > 100 || v[1].data[0] != '/' || uid < 0 ||
        !ban_uuid((char *)v[3].data, m->instance))
      return "requires socket, Agent UID and instance UUID";
    m->socket = v[1];
    m->uid = uid;
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    char boot[64] = {0};
    if (fd < 0)
      return NGX_CONF_ERROR;
    ssize_t n = read(fd, boot, sizeof(boot) - 1);
    close(fd);
    if (n < 36)
      return NGX_CONF_ERROR;
    boot[36] = 0;
    if (!ban_uuid(boot, m->boot))
      return NGX_CONF_ERROR;
    return NGX_CONF_OK;
  }
  if (text_equal(&cmd->name, "scdn_ban_scope")) {
    ngx_http_compile_complex_value_t compile;
    ngx_memzero(&compile, sizeof(compile));
    compile.cf = cf;
    compile.value = &v[1];
    compile.complex_value = &c->scope;
    if (c->scope.value.len)
      return "duplicates scope";
    return ngx_http_compile_complex_value(&compile) == NGX_OK ? NGX_CONF_OK
                                                              : NGX_CONF_ERROR;
  }
  if (c->deny || !valid_name(&v[2], 1))
    return "invalid deny rule";
  c->deny = text_equal(&v[1], "waf")  ? BAN_WAF
            : text_equal(&v[1], "cc") ? BAN_CC
                                      : 0;
  if (!c->deny)
    return "source must be waf or cc";
  c->reason = v[2];
  ngx_http_core_loc_conf_t *l =
      ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  if (l->handler)
    return "conflicts with content handler";
  l->handler = deny_handler;
  return NGX_CONF_OK;
}
static void cleanup_marker(void *data) { (void)data; }
static ban_request *request(ngx_http_request_t *r) {
  ngx_pool_cleanup_t *p;
  ban_request *c;
  ban_location *l;
  for (p = r->pool->cleanup; p; p = p->next)
    if (p->handler == cleanup_marker &&
        ((ban_request *)p->data)->owner == r->main)
      return p->data;
  l = ngx_http_get_module_loc_conf(r, ngx_http_scdn_ban_module);
  if (!l->enabled)
    return NULL;
  p = ngx_pool_cleanup_add(r->pool, sizeof(*c));
  if (!p)
    return NULL;
  c = p->data;
  ngx_memzero(c, sizeof(*c));
  p->handler = cleanup_marker;
  if (ngx_http_complex_value(r, &l->scope, &c->scope) != NGX_OK ||
      !valid_name(&c->scope, 0) ||
      !ban_address_socket(r->connection->fd, &c->ip) ||
      RAND_bytes(c->request, 16) != 1)
    return NULL;
  c->owner = r->main;
  return c;
}
static ngx_int_t enqueue(ngx_http_request_t *r, ban_request *c, unsigned source,
                         ngx_str_t *reason, const uint8_t *observed) {
  ban_event *e;
  (void)r;
  if (count == QUEUE || !view || !reason || !valid_name(reason, 1))
    return NGX_ERROR;
  e = &queue[(first + count) % QUEUE];
  ngx_memzero(e, sizeof(*e));
  e->version = BAN_VERSION;
  e->type = BAN_EVENT;
  e->sequence = ++sequence;
  memcpy(e->producer, producer, 16);
  memcpy(e->boot, main_conf->boot, 16);
  memcpy(e->instance, main_conf->instance, 16);
  memcpy(e->request, c->request, 16);
  if (observed)
    memcpy(e->observed, observed, 16);
  e->observed_ns = ban_now();
  e->generation = __atomic_load_n(&view->generation, __ATOMIC_SEQ_CST);
  e->ip = c->ip;
  e->source = source;
  memcpy(e->scope, c->scope.data, c->scope.len);
  memcpy(e->reason, reason->data, reason->len);
  count++;
  if (timer.timer_set)
    ngx_del_timer(&timer);
  ngx_add_timer(&timer, 1);
  return NGX_OK;
}
ngx_int_t ngx_http_scdn_ban_precheck(ngx_http_request_t *r) {
  ban_location *l = ngx_http_get_module_loc_conf(r, ngx_http_scdn_ban_module);
  ban_request *c;
  ban_record record;
  int result;
  char scope[96] = {0};
  if (!l->enabled || r != r->main)
    return NGX_DECLINED;
  c = request(r);
  if (!c)
    return NGX_HTTP_SERVICE_UNAVAILABLE;
  if (c->checked)
    return c->result;
  c->checked = 1;
  c->result = NGX_DECLINED;
  if (!view || !__atomic_load_n(&view->reserved[0], __ATOMIC_SEQ_CST)) {
    c->result = NGX_HTTP_SERVICE_UNAVAILABLE;
    return c->result;
  }
  result = ban_view_lookup(view, &c->ip, "", ban_now(), &record);
  if (result == 0) {
    memcpy(scope, c->scope.data, c->scope.len);
    result = ban_view_lookup(view, &c->ip, scope, ban_now(), &record);
  }
  if (result < 0)
    c->result = NGX_HTTP_SERVICE_UNAVAILABLE;
  else if (result > 0) {
    c->result = NGX_HTTP_FORBIDDEN;
    if (record.layer == 7 && record.local_waf) {
      ngx_str_t reason = ngx_string("l7-hit");
      (void)enqueue(r, c, BAN_HIT, &reason, record.id);
    }
  }
  return c->result;
}
ngx_int_t ngx_http_scdn_ban_report(ngx_http_request_t *r, ngx_uint_t source,
                                   ngx_str_t *reason) {
  ban_request *c = request(r);
  if (!c || r != r->main || source < BAN_WAF || source > BAN_CC)
    return NGX_ERROR;
  if (c->reported >= source)
    return NGX_OK;
  ngx_int_t rc = enqueue(r, c, (unsigned)source, reason, NULL);
  if (rc == NGX_OK)
    c->reported = source;
  return rc;
}
static ngx_int_t deny_handler(ngx_http_request_t *r) {
  ban_location *c = ngx_http_get_module_loc_conf(r, ngx_http_scdn_ban_module);
  ngx_int_t rc = ngx_http_scdn_ban_precheck(r);
  if (rc != NGX_DECLINED)
    return rc;
  (void)ngx_http_scdn_ban_report(r, c->deny, &c->reason);
  return NGX_HTTP_FORBIDDEN;
}
static void setter(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                   uintptr_t kind) {
  ban_request *c = request(r);
  ngx_str_t value = {v->len, v->data};
  if (!c)
    return;
  if (!kind) {
    if (valid_name(&value, 1)) {
      c->reason.len = value.len;
      c->reason.data = ngx_pnalloc(r->pool, value.len);
      if (c->reason.data)
        memcpy(c->reason.data, value.data, value.len);
    }
    return;
  }
  unsigned source = text_equal(&value, "waf")  ? BAN_WAF
                    : text_equal(&value, "cc") ? BAN_CC
                                               : 0;
  if (source)
    (void)ngx_http_scdn_ban_report(r, source, &c->reason);
}
static ngx_int_t get_variable(ngx_http_request_t *r,
                              ngx_http_variable_value_t *v, uintptr_t kind) {
  (void)r;
  (void)kind;
  v->valid = 1;
  v->not_found = 0;
  v->len = 0;
  v->data = (u_char *)"";
  return NGX_OK;
}
static ngx_int_t preconfiguration(ngx_conf_t *cf) {
  ngx_str_t names[] = {ngx_string("scdn_ban_reason"),
                       ngx_string("scdn_ban_event")};
  for (unsigned i = 0; i < 2; i++) {
    ngx_http_variable_t *v = ngx_http_add_variable(
        cf, &names[i], NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE);
    if (!v)
      return NGX_ERROR;
    v->get_handler = get_variable;
    v->set_handler = setter;
    v->data = i;
  }
  return NGX_OK;
}
static ngx_int_t postconfiguration(ngx_conf_t *cf) {
  ngx_http_core_main_conf_t *c =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_handler_pt *h =
      ngx_array_push(&c->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if (!h)
    return NGX_ERROR;
  *h = ngx_http_scdn_ban_precheck;
  return NGX_OK;
}
static void disconnect_agent(void) {
  if (agent >= 0)
    close(agent);
  agent = -1;
  awaiting = 0;
}
static int connect_agent(void) {
  struct sockaddr_un address;
  struct ucred peer;
  socklen_t size = sizeof(peer);
  ban_event hello;
  char control[CMSG_SPACE(2 * sizeof(int))];
  int fds[2];
  struct iovec io;
  struct msghdr msg;
  agent = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (agent < 0)
    return 0;
  ngx_memzero(&address, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, main_conf->socket.data, main_conf->socket.len);
  if (connect(agent, (struct sockaddr *)&address, sizeof(address)) ||
      getsockopt(agent, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
      peer.uid != main_conf->uid) {
    disconnect_agent();
    return 0;
  }
  fds[0] = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  fds[1] = open("/proc/self/ns/time", O_RDONLY | O_CLOEXEC);
  if (fds[0] < 0 || fds[1] < 0) {
    if (fds[0] >= 0)
      close(fds[0]);
    if (fds[1] >= 0)
      close(fds[1]);
    disconnect_agent();
    return 0;
  }
  ngx_memzero(&hello, sizeof(hello));
  hello.version = BAN_VERSION;
  hello.type = BAN_HELLO;
  memcpy(hello.producer, producer, 16);
  memcpy(hello.boot, main_conf->boot, 16);
  memcpy(hello.instance, main_conf->instance, 16);
  ngx_memzero(&msg, sizeof(msg));
  ngx_memzero(control, sizeof(control));
  io.iov_base = &hello;
  io.iov_len = sizeof(hello);
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(fds));
  memcpy(CMSG_DATA(c), fds, sizeof(fds));
  ssize_t n = sendmsg(agent, &msg, MSG_NOSIGNAL);
  close(fds[0]);
  close(fds[1]);
  if (n != sizeof(hello)) {
    disconnect_agent();
    return 0;
  }
  awaiting = 2;
  return 1;
}
static void tick(ngx_event_t *event) {
  ban_ack ack;
  char control[CMSG_SPACE(sizeof(int) * 4)];
  struct iovec io;
  struct msghdr msg;
  ssize_t n;
  if (ngx_exiting || ngx_quit || ngx_terminate)
    return;
  if (agent < 0 && !connect_agent()) {
    ngx_add_timer(event, 1000);
    return;
  }
  if (awaiting) {
    ngx_memzero(&msg, sizeof(msg));
    ngx_memzero(control, sizeof(control));
    io.iov_base = &ack;
    io.iov_len = sizeof(ack);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    n = recvmsg(agent, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ngx_add_timer(event, 10);
      return;
    }
    int received = -1, fd_count = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); n >= 0 && c;
         c = CMSG_NXTHDR(&msg, c)) {
      if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
        size_t bytes = c->cmsg_len - CMSG_LEN(0);
        int *f = (int *)CMSG_DATA(c);
        for (size_t i = 0; i < bytes / sizeof(int); i++) {
          fd_count++;
          if (received < 0)
            received = f[i];
          else
            close(f[i]);
        }
      }
    }
    if (n != sizeof(ack) || ack.version != BAN_VERSION ||
        (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
      if (received >= 0)
        close(received);
      disconnect_agent();
      ngx_add_timer(event, 1000);
      return;
    }
    if (awaiting == 2) {
      struct stat st;
      if (fd_count != 1 || fstat(received, &st) ||
          st.st_size != sizeof(ban_view) ||
          (fcntl(received, F_GETFL) & O_ACCMODE) != O_RDONLY) {
        if (received >= 0)
          close(received);
        disconnect_agent();
        ngx_add_timer(event, 1000);
        return;
      }
      ban_view *next =
          mmap(NULL, sizeof(ban_view), PROT_READ, MAP_SHARED, received, 0);
      close(received);
      if (next == MAP_FAILED ||
          !ban_view_valid(next, sizeof(ban_view), main_conf->boot)) {
        if (next != MAP_FAILED)
          munmap(next, sizeof(ban_view));
        disconnect_agent();
        ngx_add_timer(event, 1000);
        return;
      }
      if (view)
        munmap(view, sizeof(*view));
      view = next;
      while (count && queue[first].sequence <= ack.sequence) {
        first = (first + 1) % QUEUE;
        count--;
      }
    } else {
      if (received >= 0)
        close(received);
      if (!count || ack.sequence != queue[first].sequence || !ack.durable) {
        disconnect_agent();
        ngx_add_timer(event, 1000);
        return;
      }
      first = (first + 1) % QUEUE;
      count--;
    }
    awaiting = 0;
  }
  if (count) {
    n = send(agent, &queue[first], sizeof(ban_event),
             MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n == sizeof(ban_event))
      awaiting = 1;
    else if (errno != EAGAIN && errno != EWOULDBLOCK)
      disconnect_agent();
  }
  ngx_add_timer(event, count ? 10 : 500);
}
static ngx_int_t worker_init(ngx_cycle_t *cycle) {
  if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
    return NGX_OK;
  main_conf =
      ngx_http_cycle_get_module_main_conf(cycle, ngx_http_scdn_ban_module);
  if (!main_conf || !main_conf->socket.len)
    return NGX_OK;
  if (RAND_bytes(producer, 16) != 1)
    return NGX_ERROR;
  ngx_memzero(&timer, sizeof(timer));
  timer.handler = tick;
  timer.log = cycle->log;
  timer.cancelable = 1;
  ngx_add_timer(&timer, 1);
  return NGX_OK;
}
static void worker_exit(ngx_cycle_t *cycle) {
  (void)cycle;
  if (timer.timer_set)
    ngx_del_timer(&timer);
  disconnect_agent();
  if (view)
    munmap(view, sizeof(*view));
  view = NULL;
}
