#define _GNU_SOURCE
#include "ban_common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  if (strlen(argv[1]) >= sizeof(addr.sun_path))
    return 2;
  strcpy(addr.sun_path, argv[1]);
  int ns[2] = {open("/proc/self/ns/net", O_RDONLY),
               open("/proc/self/ns/time", O_RDONLY)};
  char boot[64] = {0};
  int file = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (file < 0 || read(file, boot, 63) < 36)
    return 2;
  close(file);
  boot[36] = 0;
  if (setgid(65534) || setuid(65534) ||
      connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
    return 3;
  ban_event event = {0};
  event.version = BAN_VERSION;
  event.type = BAN_HELLO;
  getrandom(event.producer, 16, 0);
  getrandom(event.request, 16, 0);
  ban_uuid(boot, event.boot);
  ban_uuid("00000000-0000-0000-0000-000000000100", event.instance);
  char control[CMSG_SPACE(sizeof(ns))] = {0};
  struct iovec io = {&event, sizeof(event)};
  struct msghdr msg = {0};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(ns));
  memcpy(CMSG_DATA(c), ns, sizeof(ns));
  if (sendmsg(fd, &msg, 0) != sizeof(event))
    return 4;
  close(ns[0]);
  close(ns[1]);
  ban_ack ack = {0};
  io.iov_base = &ack;
  io.iov_len = sizeof(ack);
  memset(control, 0, sizeof(control));
  if (recvmsg(fd, &msg, MSG_CMSG_CLOEXEC) != sizeof(ack))
    return 5;
  c = CMSG_FIRSTHDR(&msg);
  if (!c || c->cmsg_type != SCM_RIGHTS)
    return 5;
  int viewfd;
  memcpy(&viewfd, CMSG_DATA(c), sizeof(viewfd));
  ban_view *view =
      mmap(NULL, sizeof(ban_view), PROT_READ, MAP_SHARED, viewfd, 0);
  if (view == MAP_FAILED || !ban_view_valid(view, sizeof(*view), event.boot))
    return 6;
  void *write_map = mmap(NULL, sizeof(ban_view), PROT_READ | PROT_WRITE,
                         MAP_SHARED, viewfd, 0);
  int protected_view = write_map == MAP_FAILED;
  if (write_map != MAP_FAILED)
    munmap(write_map, sizeof(ban_view));
  if (!strcmp(argv[4], "view")) {
    int reopened = open(argv[2], O_RDWR);
    if (reopened >= 0)
      close(reopened);
    printf("{\"readonly_fd\":%s,\"cannot_reopen\":%s}\n",
           protected_view ? "true" : "false", reopened < 0 ? "true" : "false");
    return 0;
  }
  event.type = BAN_EVENT;
  event.sequence = 1;
  event.observed_ns = ban_now();
  event.generation = __atomic_load_n(&view->generation, __ATOMIC_SEQ_CST);
  ban_address_parse(argv[3], &event.ip);
  strcpy(event.scope, "alpha");
  strcpy(event.reason, "waf-rule");
  event.source = BAN_WAF;
  if (!strcmp(argv[4], "stale"))
    event.observed_ns = 1;
  if (!strcmp(argv[4], "unknown"))
    strcpy(event.reason, "unregistered");
  if (send(fd, &event, sizeof(event), 0) != sizeof(event))
    return 7;
  ssize_t n = recv(fd, &ack, sizeof(ack), 0);
  if (!strcmp(argv[4], "unknown")) {
    printf("{\"rejected\":%s}\n", n <= 0 ? "true" : "false");
    return 0;
  }
  if (n != sizeof(ack))
    return 8;
  uint64_t durable = ack.durable;
  if (send(fd, &event, sizeof(event), 0) != sizeof(event) ||
      recv(fd, &ack, sizeof(ack), 0) != sizeof(ack))
    return 9;
  printf("{\"duplicate_receipt\":%s,\"durable\":%s}\n",
         durable == ack.durable ? "true" : "false", durable ? "true" : "false");
  munmap(view, sizeof(*view));
  close(viewfd);
  close(fd);
  return 0;
}
