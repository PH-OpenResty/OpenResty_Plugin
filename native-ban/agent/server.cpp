#include "ban.hpp"
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <poll.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
namespace ban {
static int listener(const std::string &path, int type, mode_t mode,
                    uint32_t gid) {
  require(path.size() < sizeof(sockaddr_un::sun_path), "socket_path_length");
  struct stat st;
  if (!lstat(path.c_str(), &st)) {
    require(S_ISSOCK(st.st_mode) && st.st_uid == geteuid(),
            "socket_path_occupied");
    require(!unlink(path.c_str()), "socket_unlink");
  } else
    require(errno == ENOENT, "socket_lstat");
  int fd = socket(AF_UNIX, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  require(fd >= 0, "socket_create");
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path.c_str());
  require(!bind(fd, (sockaddr *)&addr, sizeof(addr)) &&
              !chmod(path.c_str(), mode) &&
              !chown(path.c_str(), geteuid(), gid) && !listen(fd, 64),
          "socket_bind");
  return fd;
}
static bool credential(int fd, uint32_t *uid) {
  ucred peer{};
  socklen_t n = sizeof(peer);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n))
    return false;
  *uid = peer.uid;
  return true;
}
static bool namespace_same(int fd, const char *path, int type) {
  struct stat a, b;
  int own = open(path, O_RDONLY | O_CLOEXEC);
  bool ok = own >= 0 && ioctl(fd, NS_GET_NSTYPE) == type && !fstat(fd, &a) &&
            !fstat(own, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
  if (own >= 0)
    close(own);
  return ok;
}
static void reply(int fd, const ban_ack &ack, int view = -1) {
  iovec io{(void *)&ack, sizeof(ack)};
  msghdr msg{};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  char control[CMSG_SPACE(sizeof(int))] = {0};
  if (view >= 0) {
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    auto *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &view, sizeof(view));
  }
  require(sendmsg(fd, &msg, MSG_NOSIGNAL) == sizeof(ack), "event_ack_send");
}
struct Client {
  int fd;
  uint32_t uid;
  bool hello = false;
  std::string producer, instance;
};
struct ReceivedEvent {
  int fd;
  ban_event event;
  uint32_t uid;
};
static bool handle_event(Engine &e, Client &client,
                         std::vector<ReceivedEvent> &batch) {
  ban_event event{};
  char control[CMSG_SPACE(sizeof(int) * 8)] = {0};
  iovec io{&event, sizeof(event)};
  msghdr msg{};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  ssize_t n = recvmsg(client.fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return true;
  if (n <= 0)
    return false;
  std::vector<int> fds;
  for (auto *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
      size_t size = c->cmsg_len - CMSG_LEN(0);
      auto *p = (int *)CMSG_DATA(c);
      for (size_t i = 0; i < size / sizeof(int); i++)
        fds.push_back(p[i]);
    }
  }
  try {
    require(n == sizeof(event) && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
                event.version == BAN_VERSION,
            "event_frame");
    std::lock_guard<std::mutex> lock(e.mutex);
    uint8_t boot[16];
    require(ban_uuid(e.conf.boot.c_str(), boot) &&
                !memcmp(boot, event.boot, 16),
            "hello_boot");
    if (event.type == BAN_HELLO) {
      require(!client.hello && event.sequence == 0 &&
                  client.uid == e.conf.worker_uid &&
                  e.conf.instances.count(hex(event.instance, 16)),
              "hello_identity");
      require(fds.size() == 2 &&
                  namespace_same(fds[0], "/proc/self/ns/net", CLONE_NEWNET) &&
                  namespace_same(fds[1], "/proc/self/ns/time", CLONE_NEWTIME),
              "namespace_mismatch");
      client.producer = hex(event.producer, 16);
      client.instance = hex(event.instance, 16);
      client.hello = true;
      auto sequence = e.producer_sequence(client.producer);
      ban_ack ack{BAN_VERSION,
                  !e.conf.storage.persistent && sequence == 0
                      ? BAN_ACK_MEMORY_RESET
                      : 0u,
                  sequence, 1};
      reply(client.fd, ack, e.view->readonly);
    } else {
      require(client.hello && fds.empty() &&
                  client.producer == hex(event.producer, 16) &&
                  client.instance == hex(event.instance, 16),
              "event_connection_identity");
      batch.push_back({client.fd, event, client.uid});
    }
    for (int fd : fds)
      close(fd);
    return true;
  } catch (...) {
    for (int fd : fds)
      close(fd);
    return false;
  }
}
static bool transfer(int fd, void *bytes, size_t length, bool sendit) {
  size_t done = 0;
  while (done < length) {
    ssize_t n =
        sendit ? send(fd, (char *)bytes + done, length - done, MSG_NOSIGNAL)
               : recv(fd, (char *)bytes + done, length - done, 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    done += (size_t)n;
  }
  return true;
}
/* Length-prefixed stream RPC: only the authenticated Sync worker UID may call
 * the authority bridge; identity is injected by Sync after mTLS validation. */
static void stream_client(Engine &e, int fd, bool admin) {
  timeval timeout{3, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  uint32_t uid = 0, size = 0;
  J result;
  int status = 200;
  try {
    require(credential(fd, &uid) && (admin ? uid == 0 : uid == e.conf.sync_uid),
            "rpc_uid");
    require(transfer(fd, &size, 4, false) && size > 0 && size <= BAN_MAX_FRAME,
            "rpc_size");
    std::string body(size, '\0');
    require(transfer(fd, body.data(), body.size(), false), "rpc_read");
    auto request = parse(body);
    std::lock_guard<std::mutex> lock(e.mutex);
    if (admin)
      result = e.query(request);
    else {
      keys(request, "node operation body");
      result = e.bridge(str(request, "node"), str(request, "operation"),
                        get(request, "body"));
    }
  } catch (const std::exception &error) {
    status = 400;
    result = object();
    set(result, "error", std::string(error.what()));
  }
  auto body = dump(result);
  uint32_t header[2] = {(uint32_t)status, (uint32_t)body.size()};
  (void)transfer(fd, header, sizeof(header), true);
  (void)transfer(fd, body.data(), body.size(), true);
  close(fd);
}
void serve(Engine &e, std::atomic<bool> &stop, std::atomic<bool> &reload,
           const std::string &config_path) {
  int events = listener(e.conf.event_socket, SOCK_SEQPACKET, 0660,
                        e.conf.worker_gid),
      admin = listener(e.conf.admin_socket, SOCK_STREAM, 0600, 0),
      sync =
          listener(e.conf.cluster_socket, SOCK_STREAM, 0660, e.conf.worker_gid);
  std::vector<Client> clients;
  std::atomic<unsigned> connections{0};
  struct RpcThread {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };
  std::vector<RpcThread> threads;
  std::thread network([&] {
    while (!stop) {
      e.cluster_cycle();
      for (int n = 0; n < e.conf.poll_ms / 50 && !stop; n++)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  });
  auto last = ban_now();
  while (!stop) {
    if (reload.exchange(false)) {
      try {
        auto next = config_read(config_path);
        std::lock_guard<std::mutex> lock(e.mutex);
        e.reload(next);
      } catch (const std::exception &error) {
        std::lock_guard<std::mutex> lock(e.mutex);
        e.policy_error = error.what();
      }
    }
    std::vector<pollfd> polls{
        {events, POLLIN, 0}, {admin, POLLIN, 0}, {sync, POLLIN, 0}};
    for (auto &c : clients)
      polls.push_back({c.fd, POLLIN, 0});
    int n = poll(polls.data(), polls.size(), 50);
    if (n < 0 && errno == EINTR)
      continue;
    require(n >= 0, "poll_failed");
    std::vector<ReceivedEvent> batch;
    for (size_t i = clients.size(); i > 0; i--) {
      auto index = i - 1;
      if (polls[index + 3].revents &&
          (polls[index + 3].revents & (POLLHUP | POLLERR) ||
           !handle_event(e, clients[index], batch))) {
        close(clients[index].fd);
        clients.erase(clients.begin() + (long)index);
      }
    }
    if (!batch.empty()) {
      std::vector<std::optional<ban_ack>> acks(batch.size());
      try {
        std::vector<std::pair<ban_event, uint32_t>> inputs;
        inputs.reserve(batch.size());
        for (auto &item : batch)
          inputs.push_back({item.event, item.uid});
        std::lock_guard<std::mutex> guard(e.mutex);
        acks = e.events(inputs);
      } catch (const std::exception &error) {
        std::lock_guard<std::mutex> guard(e.mutex);
        e.sync_error = error.what();
      }
      for (size_t i = 0; i < batch.size(); i++) {
        bool ok = acks[i].has_value();
        if (ok)
          try {
            reply(batch[i].fd, *acks[i]);
          } catch (...) {
            ok = false;
          }
        if (!ok)
          for (auto it = clients.begin(); it != clients.end(); ++it)
            if (it->fd == batch[i].fd) {
              close(it->fd);
              clients.erase(it);
              break;
            }
      }
    }
    for (unsigned kind = 0; kind < 3; kind++)
      if (polls[kind].revents & POLLIN) {
        int fd = accept4(polls[kind].fd, nullptr, nullptr,
                         SOCK_CLOEXEC | (kind == 0 ? SOCK_NONBLOCK : 0));
        if (fd < 0)
          continue;
        uint32_t uid;
        if (kind == 0) {
          if (clients.size() >= 128 || !credential(fd, &uid)) {
            close(fd);
            continue;
          }
          clients.push_back({fd, uid, false, "", ""});
        } else if (connections >= 16) {
          close(fd);
        } else {
          connections++;
          auto done = std::make_shared<std::atomic<bool>>(false);
          threads.push_back({std::thread([&, fd, kind, done] {
                               stream_client(e, fd, kind == 1);
                               connections--;
                               *done = true;
                             }),
                             done});
        }
      }
    if (ban_now() - last >= 1000000000u) {
      last = ban_now();
      try {
        std::lock_guard<std::mutex> lock(e.mutex);
        e.tick();
      } catch (const std::exception &error) {
        std::lock_guard<std::mutex> lock(e.mutex);
        e.sync_error = error.what();
      }
    }
    // Bound thread objects as well as concurrent connections.
    for (auto it = threads.begin(); it != threads.end();) {
      if (*it->done) {
        it->thread.join();
        it = threads.erase(it);
      } else
        ++it;
    }
  }
  network.join();
  for (auto &t : threads)
    t.thread.join();
  for (auto &c : clients)
    close(c.fd);
  close(events);
  close(admin);
  close(sync);
  unlink(e.conf.event_socket.c_str());
  unlink(e.conf.admin_socket.c_str());
  unlink(e.conf.cluster_socket.c_str());
}
} // namespace ban
