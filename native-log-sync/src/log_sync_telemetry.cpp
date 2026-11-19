#include "log_sync.hpp"
#include <algorithm>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <cmath>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>

namespace logs {
static uint64_t wall_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
static void real(const J &j, const char *key, double value) {
  json_object_object_add(j.get(), key,
                         std::isfinite(value) ? json_object_new_double(value)
                                              : nullptr);
}
static void missing(const J &j, const char *key) {
  json_object_object_add(j.get(), key, nullptr);
}
static bool present(const J &j, const char *key) {
  json_object *p = nullptr;
  return j && json_object_object_get_ex(j.get(), key, &p) && p != nullptr;
}
static std::string proc(const Config &c, const char *path) {
  auto root = c.telemetry.proc_root;
  if (root == "/proc" && !strncmp(path, "/net/", 5))
    root += "/" + std::to_string(getpid());
  return read_file(root + path, 8 * 1024 * 1024);
}
static std::map<std::string, uint64_t> values(const std::string &text) {
  std::map<std::string, uint64_t> out;
  std::istringstream lines(text);
  std::string line, key;
  while (std::getline(lines, line)) {
    std::istringstream row(line);
    uint64_t value;
    if (row >> key >> value) {
      if (!key.empty() && key.back() == ':')
        key.pop_back();
      out[key] = value;
    }
  }
  return out;
}
static std::string leaf(const std::string &dir, const std::string &name) {
  return dir + "/" + name;
}
static std::vector<std::string> children(const std::string &path,
                                         size_t limit) {
  DIR *raw = opendir(path.c_str());
  need(raw != nullptr, IO);
  std::unique_ptr<DIR, int (*)(DIR *)> owner(raw, closedir);
  std::vector<std::string> names;
  while (auto *entry = readdir(raw)) {
    std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    need(names.size() < limit, CAPACITY);
    names.push_back(name);
  }
  return names;
}
static bool digits(const std::string &s) {
  return !s.empty() && std::all_of(s.begin(), s.end(),
                                   [](char c) { return c >= '0' && c <= '9'; });
}
static J protocols(const Config &c) {
  auto out = obj();
  for (auto path : {"/net/snmp", "/net/netstat"}) {
    std::istringstream stream(proc(c, path));
    std::string header, line;
    while (std::getline(stream, header) && std::getline(stream, line)) {
      std::istringstream keys(header), numbers(line);
      std::string group, other, name, value;
      keys >> group;
      numbers >> other;
      need(group == other, STATE);
      while (keys >> name && numbers >> value) {
        auto key = group.substr(0, group.size() - 1) + "_" + name;
        if (value == "-1")
          real(out, key.c_str(), -1);
        else {
          need(digits(value), STATE);
          put(out, key.c_str(), std::stoull(value));
        }
      }
    }
  }
  try {
    std::istringstream lines(proc(c, "/net/snmp6"));
    std::string key;
    uint64_t n;
    while (lines >> key >> n)
      put(out, key.c_str(), n);
  } catch (const Failure &) {
  }
  return out;
}
static J sockets(const Config &c) {
  auto out = obj();
  std::set<uint64_t> owned;
  bool complete = true;
  std::set<std::string> processes;
  if (!c.telemetry.pid_file.empty()) {
    auto value = read_file(c.telemetry.pid_file, 128);
    value.erase(std::remove_if(value.begin(), value.end(),
                               [](char ch) {
                                 return ch == '\r' || ch == '\n' || ch == ' ';
                               }),
                value.end());
    need(digits(value), STATE);
    processes.insert(value);
    /* Worker/master relationships, rather than a process-name match,
     * keep unrelated nginx installations outside this scope. */
    auto names = children(c.telemetry.proc_root, 131072);
    for (unsigned pass = 0; pass < 3; pass++)
      for (auto &pid : names)
        if (digits(pid) && !processes.count(pid)) {
          try {
            auto status =
                read_file(leaf(c.telemetry.proc_root, pid) + "/status", 65536);
            std::istringstream lines(status);
            std::string line;
            while (std::getline(lines, line))
              if (line.compare(0, 5, "PPid:") == 0) {
                auto parent = line.substr(5);
                parent.erase(std::remove_if(parent.begin(), parent.end(),
                                            [](char ch) {
                                              return ch == ' ' || ch == '\t';
                                            }),
                             parent.end());
                if (processes.count(parent))
                  processes.insert(pid);
                break;
              }
          } catch (const Failure &) {
          }
        }
    for (auto &pid : processes) {
      auto directory = leaf(c.telemetry.proc_root, pid) + "/fd";
      try {
        for (auto &fd : children(directory, 1048576)) {
          char link[256];
          ssize_t n =
              readlink(leaf(directory, fd).c_str(), link, sizeof(link) - 1);
          if (n < 0) {
            /* A closed connection, including the directory descriptor used
             * for enumeration itself, can disappear between list/readlink. */
            if (errno != ENOENT)
              complete = false;
            continue;
          }
          link[n] = 0;
          std::string target = link;
          if (target.compare(0, 8, "socket:[") == 0 && target.back() == ']') {
            auto inode = target.substr(8, target.size() - 9);
            if (digits(inode))
              owned.insert(std::stoull(inode));
          }
        }
      } catch (const Failure &) {
        if (pid != value)
          complete = false;
      }
    }
    put(out, "nginx_processes", uint64_t(processes.size()));
    put(out, "nginx_socket_scope_valid", complete ? uint64_t(1) : uint64_t(0));
  } else {
    complete = false;
    put(out, "nginx_socket_scope_valid", uint64_t(0));
  }
  for (auto protocol : {"tcp", "udp"}) {
    uint64_t total = 0, nginx = 0, connected = 0, established = 0,
             listening = 0, syn_sent = 0, syn_recv = 0;
    for (auto suffix : {"", "6"}) {
      std::string name = std::string("/net/") + protocol + suffix;
      std::istringstream lines(proc(c, name.c_str()));
      std::string line;
      std::getline(lines, line);
      while (std::getline(lines, line)) {
        std::istringstream row(line);
        std::vector<std::string> parts;
        std::string part;
        while (row >> part)
          parts.push_back(part);
        if (parts.size() < 10)
          continue;
        total++;
        if (!digits(parts[9]) || !owned.count(std::stoull(parts[9])))
          continue;
        nginx++;
        if (parts[3] == "01") {
          connected++;
          established++;
        }
        if (parts[3] == "0A")
          listening++;
        if (parts[3] == "02")
          syn_sent++;
        if (parts[3] == "03")
          syn_recv++;
      }
    }
    put(out, (std::string("host_") + protocol + "_sockets").c_str(), total);
    if (complete) {
      put(out, (std::string("nginx_") + protocol + "_sockets").c_str(), nginx);
      if (!strcmp(protocol, "tcp")) {
        put(out, "nginx_tcp_established", established);
        put(out, "nginx_tcp_listen", listening);
        put(out, "nginx_tcp_syn_sent", syn_sent);
        put(out, "nginx_tcp_syn_recv", syn_recv);
      } else
        put(out, "nginx_udp_connected_sockets", connected);
    } else {
      missing(out, (std::string("nginx_") + protocol + "_sockets").c_str());
      if (!strcmp(protocol, "tcp")) {
        for (auto key : {"nginx_tcp_established", "nginx_tcp_listen",
                         "nginx_tcp_syn_sent", "nginx_tcp_syn_recv"})
          missing(out, key);
      } else
        missing(out, "nginx_udp_connected_sockets");
    }
  }
  missing(out, "nginx_quic_sessions");
  return out;
}
static J ban_rpc(const std::string &path, const char *operation) {
  need(path.size() < sizeof(sockaddr_un::sun_path), CONFIG);
  Fd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  need(fd.value >= 0, IO);
  timeval timeout{1, 0};
  setsockopt(fd.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd.value, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path.c_str(), path.size() + 1);
  need(!connect(fd.value, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)),
       IO);
  auto request = obj();
  put(request, "operation", operation);
  auto body = dump(request);
  uint32_t size = body.size();
  std::string frame(reinterpret_cast<char *>(&size), 4);
  frame += body;
  size_t done = 0;
  while (done < frame.size()) {
    ssize_t n = ::send(fd.value, frame.data() + done, frame.size() - done,
                       MSG_NOSIGNAL);
    need(n > 0, IO);
    done += n;
  }
  auto read_exact = [&](char *p, size_t count) {
    size_t n = 0;
    while (n < count) {
      ssize_t r = recv(fd.value, p + n, count - n, 0);
      need(r > 0, IO);
      n += r;
    }
  };
  uint32_t header[2];
  read_exact(reinterpret_cast<char *>(header), 8);
  need(header[0] == 200 && header[1] <= 4 * 1024 * 1024, BACKEND);
  std::string response(header[1], '\0');
  read_exact(&response[0], response.size());
  return parse(response);
}
static uint64_t metric_sum(const std::string &data, const std::string &prefix,
                           const std::string &kind = "") {
  uint64_t result = 0;
  std::istringstream lines(data);
  std::string line;
  while (std::getline(lines, line))
    if (line.compare(0, prefix.size(), prefix) == 0 &&
        (kind.empty() ||
         line.find("kind=\"" + kind + "\"") != std::string::npos)) {
      auto at = line.rfind(' ');
      if (at != std::string::npos) {
        auto n = line.substr(at + 1);
        if (digits(n))
          result += std::stoull(n);
      }
    }
  return result;
}
J site_catalog(const std::string &path) {
  auto raw = read_file(path, 8 * 1024 * 1024);
  if (raw.find_first_not_of(" \r\n\t") != std::string::npos &&
      raw[raw.find_first_not_of(" \r\n\t")] == '[')
    return parse(raw);
  std::vector<std::string> tokens;
  std::string token;
  bool quote = false, escape = false, comment = false;
  for (char ch : raw) {
    if (comment) {
      if (ch == '\n')
        comment = false;
      continue;
    }
    if (escape) {
      token += ch;
      escape = false;
      continue;
    }
    if (quote) {
      if (ch == '\\')
        escape = true;
      else if (ch == '"')
        quote = false;
      else
        token += ch;
      continue;
    }
    if (ch == '"') {
      quote = true;
      continue;
    }
    if (ch == '#') {
      comment = true;
      continue;
    }
    if (ch == '{' || ch == '}' || ch == ';' || ch == ' ' || ch == '\t' ||
        ch == '\r' || ch == '\n') {
      if (!token.empty()) {
        tokens.push_back(token);
        token.clear();
      }
      if (ch == '{' || ch == '}' || ch == ';')
        tokens.emplace_back(1, ch);
    } else
      token += ch;
  }
  need(!quote && !escape, STATE);
  auto out = arr();
  J site;
  unsigned depth = 0, site_depth = 0;
  for (size_t i = 0; i < tokens.size(); i++) {
    auto &v = tokens[i];
    if (v == "site" && i + 2 < tokens.size() && tokens[i + 2] == "{") {
      site = obj();
      put(site, "id", tokens[i + 1]);
      put(site, "hosts", arr());
      put(site, "enabled", uint64_t(1));
      json_object_array_add(out.get(), json_object_get(site.get()));
      site_depth = depth + 1;
    }
    if (v == "{")
      depth++;
    else if (v == "}") {
      need(depth > 0, STATE);
      if (site && depth == site_depth)
        site = {};
      depth--;
    } else if (site && depth == site_depth && i + 1 < tokens.size()) {
      if (v == "host") {
        auto hosts = get(site, "hosts");
        json_object_array_add(hosts.get(),
                              json_object_new_string(tokens[i + 1].c_str()));
      }
      if (v == "enabled")
        put(site, "enabled", tokens[i + 1] == "on" ? uint64_t(1) : uint64_t(0));
    }
  }
  need(depth == 0, STATE);
  return out;
}
J sample(const Config &c, J previous) {
  auto out = obj(), health = obj();
  uint64_t captured = wall_ms();
  put(out, "time", captured);
  put(out, "node", c.node);
  put(out, "record_type", "node_sample");
  put(out, "sampling_scope", "host_network_namespace_and_nginx_pid_tree");
  for (auto key : {"sync_ok",
                   "sync_sequence",
                   "ban_ready",
                   "active_bans",
                   "sites",
                   "site_hosts",
                   "ban_records",
                   "cpu_pct",
                   "load1",
                   "cpu_count",
                   "mem_total",
                   "mem_available",
                   "mem_pct",
                   "net_rx",
                   "net_tx",
                   "rx_bps",
                   "tx_bps",
                   "cache_disk_total",
                   "cache_disk_free",
                   "cache_disk_pct",
                   "api_web",
                   "api_api",
                   "api_ai",
                   "api_stream",
                   "api_grpc",
                   "api_websocket",
                   "native_requests",
                   "native_bytes",
                   "nginx_stats",
                   "kernel_drop_counter",
                   "kernel_drop_delta",
                   "kernel_drop_pps",
                   "packets"})
    missing(out, key);
  double duration = previous && number(previous, "time") < captured
                        ? (captured - number(previous, "time")) / 1000.0
                        : 0;
  try {
    auto boot = proc(c, "/sys/kernel/random/boot_id");
    boot.erase(std::remove(boot.begin(), boot.end(), '\n'), boot.end());
    put(out, "boot_id", boot);
    if (previous && text(previous, "boot_id") != boot)
      duration = 0;
  } catch (const Failure &) {
    put(out, "boot_id", "");
    duration = 0;
  }
  try {
    std::istringstream cpu(proc(c, "/stat"));
    std::string name;
    cpu >> name;
    uint64_t v, total = 0, idle = 0;
    unsigned i = 0;
    while (i < 8 && cpu >> v) {
      total += v;
      if (i == 3 || i == 4)
        idle += v;
      i++;
    }
    need(i == 8, STATE);
    put(out, "cpu_total", total);
    put(out, "cpu_idle", idle);
    missing(out, "cpu_pct");
    if (previous && duration > 0 && total > number(previous, "cpu_total") &&
        idle >= number(previous, "cpu_idle"))
      real(out, "cpu_pct",
           100.0 * (1.0 - double(idle - number(previous, "cpu_idle")) /
                              double(total - number(previous, "cpu_total"))));
    auto memory = values(proc(c, "/meminfo"));
    uint64_t mem = memory.at("MemTotal") * 1024,
             available = memory.at("MemAvailable") * 1024;
    put(out, "mem_total", mem);
    put(out, "mem_available", available);
    real(out, "mem_pct", mem ? 100.0 * (mem - available) / mem : 0);
    std::istringstream load(proc(c, "/loadavg"));
    double one = 0;
    load >> one;
    real(out, "load1", one);
    put(out, "cpu_count", uint64_t(sysconf(_SC_NPROCESSORS_ONLN)));
    put(health, "host", uint64_t(1));
  } catch (...) {
    put(health, "host", uint64_t(0));
    for (auto k : {"cpu_pct", "mem_total", "mem_available", "mem_pct", "load1",
                   "cpu_count"})
      missing(out, k);
  }
  try {
    std::istringstream lines(proc(c, "/net/dev"));
    std::string line;
    uint64_t rx = 0, tx = 0;
    while (std::getline(lines, line)) {
      auto at = line.find(':');
      if (at == std::string::npos)
        continue;
      auto name = line.substr(0, at);
      name.erase(std::remove(name.begin(), name.end(), ' '), name.end());
      if (name == "lo")
        continue;
      std::istringstream row(line.substr(at + 1));
      uint64_t value;
      for (unsigned i = 0; i < 16 && row >> value; i++) {
        if (i == 0)
          rx += value;
        if (i == 8)
          tx += value;
      }
    }
    put(out, "net_rx", rx);
    put(out, "net_tx", tx);
    missing(out, "rx_bps");
    missing(out, "tx_bps");
    if (previous && duration > 0 && rx >= number(previous, "net_rx") &&
        tx >= number(previous, "net_tx")) {
      real(out, "rx_bps", 8.0 * (rx - number(previous, "net_rx")) / duration);
      real(out, "tx_bps", 8.0 * (tx - number(previous, "net_tx")) / duration);
    }
    put(out, "network_protocols", protocols(c));
    put(out, "connections", sockets(c));
    put(health, "network", uint64_t(1));
  } catch (...) {
    put(health, "network", uint64_t(0));
    missing(out, "connections");
    missing(out, "network_protocols");
  }
  if (!c.telemetry.cache_path.empty())
    try {
      struct statvfs disk{};
      need(!statvfs(c.telemetry.cache_path.c_str(), &disk), IO);
      uint64_t total = disk.f_blocks * disk.f_frsize,
               free = disk.f_bavail * disk.f_frsize;
      put(out, "cache_disk_total", total);
      put(out, "cache_disk_free", free);
      real(out, "cache_disk_pct", total ? 100.0 * (total - free) / total : 0);
      put(health, "cache_disk", uint64_t(1));
    } catch (...) {
      put(health, "cache_disk", uint64_t(0));
    }
  auto status = obj();
  for (auto &endpoint : c.telemetry.endpoints)
    try {
      if (c.stop && c.stop->load())
        throw Failure(TRANSPORT);
      auto raw = fetch_status(c, endpoint);
      if (endpoint.format == "json") {
        auto data = parse(raw);
        put(status, endpoint.id.c_str(), data);
        if (endpoint.id == "sync") {
          put(out, "sync_ok",
              text(data, "sync_state") == "applied" &&
                      text(data, "business_health") == "passed"
                  ? uint64_t(1)
                  : uint64_t(0));
          auto seq = get(data, "sequence", false);
          put(out, "sync_sequence",
              seq ? (json_object_is_type(seq.get(), json_type_string)
                         ? str(seq)
                         : dump(seq))
                  : "");
        }
        if (endpoint.id == "nginx")
          put(out, "nginx_stats", data);
      } else {
        put(status, endpoint.id.c_str(), raw);
        if (endpoint.id == "edge") {
          put(out, "native_requests",
              metric_sum(raw, "scdn_edge_requests_total{"));
          put(out, "native_bytes", metric_sum(raw, "scdn_edge_bytes_total{"));
        }
        if (endpoint.id == "api")
          for (auto kind : {"web", "api", "ai", "stream", "grpc", "websocket"})
            put(out, (std::string("api_") + kind).c_str(),
                metric_sum(raw, "scdn_api_requests_total{", kind));
      }
      put(health, endpoint.id.c_str(), uint64_t(1));
    } catch (...) {
      put(health, endpoint.id.c_str(), uint64_t(0));
    }
  put(out, "status", status);
  if (!c.telemetry.sites_file.empty())
    try {
      auto catalog = site_catalog(c.telemetry.sites_file), sites = arr(),
           hosts = arr();
      put(out, "site_inventory", catalog);
      for (size_t i = 0; i < json_object_array_length(catalog.get()); i++) {
        auto site =
            own(json_object_get(json_object_array_get_idx(catalog.get(), i)));
        json_object *enabled = nullptr;
        bool on = !json_object_object_get_ex(site.get(), "enabled", &enabled) ||
                  json_object_get_boolean(enabled);
        if (!on)
          continue;
        json_object_array_add(sites.get(),
                              json_object_new_string(text(site, "id").c_str()));
        auto names = get(site, "hosts");
        for (size_t n = 0; n < json_object_array_length(names.get()); n++)
          json_object_array_add(
              hosts.get(),
              json_object_get(json_object_array_get_idx(names.get(), n)));
      }
      put(out, "sites", sites);
      put(out, "site_hosts", hosts);
      put(health, "sites", uint64_t(1));
    } catch (...) {
      put(health, "sites", uint64_t(0));
    }
  if (!c.telemetry.ban_socket.empty())
    try {
      auto data = ban_rpc(c.telemetry.ban_socket, "status"),
           records = get(ban_rpc(c.telemetry.ban_socket, "list"), "records");
      auto safe = arr();
      for (size_t i = 0; i < json_object_array_length(records.get()); i++) {
        auto record = own(
                 json_object_get(json_object_array_get_idx(records.get(), i))),
             item = obj();
        for (auto key : {"ip", "scope", "layer", "ban_id", "expires"}) {
          auto v = get(record, key, false);
          if (v)
            put(item, key, v);
        }
        unsigned family = 0;
        put(item, "internal",
            internal_ip(text(item, "ip"), family) ? uint64_t(1) : uint64_t(0));
        if (text(item, "scope") == "cdn-unregistered")
          put(item, "scope", "__unregistered__");
        json_object_array_add(safe.get(), json_object_get(item.get()));
      }
      auto ready = get(data, "kernel_ready");
      need(json_object_is_type(ready.get(), json_type_boolean) ||
               json_object_is_type(ready.get(), json_type_int),
           STATE);
      put(out, "ban_ready",
          json_object_get_boolean(ready.get()) ? uint64_t(1) : uint64_t(0));
      put(out, "active_bans", uint64_t(json_object_array_length(safe.get())));
      put(out, "ban_records", dump(safe));
      put(health, "ban", uint64_t(1));
    } catch (...) {
      put(health, "ban", uint64_t(0));
      missing(out, "active_bans");
      missing(out, "ban_ready");
    }
  if (!c.telemetry.ban_counter_map.empty())
    try {
      Fd fd(bpf_obj_get(c.telemetry.ban_counter_map.c_str()));
      need(fd.value >= 0, IO);
      struct bpf_map_info info{};
      uint32_t info_size = sizeof(info);
      need(!bpf_obj_get_info_by_fd(fd.value, &info, &info_size) &&
               info.type == BPF_MAP_TYPE_PERCPU_ARRAY && info.key_size == 4 &&
               info.value_size == 8 && info.max_entries >= 1,
           STATE);
      int count = libbpf_num_possible_cpus();
      need(count > 0 && count <= 8192, STATE);
      std::vector<uint64_t> counters(count);
      uint32_t key = 0;
      need(!bpf_map_lookup_elem(fd.value, &key, counters.data()), IO);
      uint64_t total = 0;
      for (auto v : counters)
        total += v;
      put(out, "kernel_drop_counter", total);
      missing(out, "kernel_drop_delta");
      missing(out, "kernel_drop_pps");
      if (previous && duration > 0 &&
          present(previous, "kernel_drop_counter") &&
          total >= number(previous, "kernel_drop_counter")) {
        put(out, "kernel_drop_delta",
            total - number(previous, "kernel_drop_counter"));
        real(out, "kernel_drop_pps",
             (total - number(previous, "kernel_drop_counter")) / duration);
      }
      put(health, "kernel_drop", uint64_t(1));
    } catch (...) {
      put(health, "kernel_drop", uint64_t(0));
      missing(out, "kernel_drop_counter");
    }
  if (!c.telemetry.packet_file.empty())
    try {
      auto packet = parse(read_file(c.telemetry.packet_file, 4 * 1024 * 1024));
      need(text(packet, "node", c.node) == c.node, STATE);
      auto stamp = number(packet, "time_ms");
      auto packet_now = wall_ms();
      need(stamp <= packet_now + 1000 && stamp + 5000 >= packet_now, STATE);
      put(out, "packets", packet);
      put(health, "packets", uint64_t(1));
      auto privileged = get(packet, "privileged_sample", false);
      if (privileged) {
        for (auto key : {"connections", "ban_ready", "active_bans",
                         "ban_records", "kernel_drop_counter"})
          if (present(privileged, key))
            put(out, key, get(privileged, key));
        auto helper_health = get(privileged, "health", false);
        if (helper_health)
          for (auto key : {"ban", "kernel_drop"})
            if (present(helper_health, key) && number(helper_health, key) == 1)
              put(health, key, uint64_t(1));
        if (present(privileged, "kernel_drop_counter")) {
          uint64_t total = number(privileged, "kernel_drop_counter");
          missing(out, "kernel_drop_delta");
          missing(out, "kernel_drop_pps");
          if (previous && duration > 0 &&
              present(previous, "kernel_drop_counter") &&
              total >= number(previous, "kernel_drop_counter")) {
            put(out, "kernel_drop_delta",
                total - number(previous, "kernel_drop_counter"));
            real(out, "kernel_drop_pps",
                 (total - number(previous, "kernel_drop_counter")) / duration);
          }
        }
      }
      auto rates = obj();
      for (auto direction : {"ingress", "egress"}) {
        auto row = obj(), values = get(packet, direction);
        for (auto key : {"tcp_packets", "tcp_ack", "tcp_syn", "tcp_syn_ack",
                         "tcp_syn_only", "tcp_fin", "tcp_rst", "udp_packets"}) {
          missing(row, key);
          if (previous && present(previous, "packets") && duration > 0) {
            auto old = get(previous, "packets");
            if (text(old, "session") == text(packet, "session") &&
                stamp > number(old, "time_ms")) {
              auto before = get(old, direction);
              auto n = number(values, key);
              if (n >= number(before, key))
                real(row, key,
                     1000.0 * (n - number(before, key)) /
                         (stamp - number(old, "time_ms")));
            }
          }
        }
        put(rates, direction, row);
      }
      put(out, "packet_pps", rates);
    } catch (...) {
      put(health, "packets", uint64_t(0));
      missing(out, "packets");
    }
  auto collection = obj();
  put(collection, "success", uint64_t(0));
  put(collection, "inserted", uint64_t(0));
  put(collection, "invalid", uint64_t(0));
  put(collection, "source_files", uint64_t(0));
  put(collection, "completed_files", uint64_t(0));
  put(collection, "error", "sender_unavailable");
  try {
    auto envelope =
        parse(read_file(c.state + "/state.json", 128 * 1024 * 1024));
    auto payload = text(envelope, "payload");
    need(sha(payload) == text(envelope, "sha256"), STATE);
    auto state = parse(payload), files = get(state, "files");
    auto confirmed = number(state, "confirmed_events");
    put(collection, "confirmed_events", confirmed);
    auto invalid = number(state, "invalid_records");
    put(collection, "invalid_records", invalid);
    if (previous && present(previous, "collection")) {
      auto before = get(previous, "collection");
      if (confirmed >= number(before, "confirmed_events"))
        put(collection, "inserted",
            confirmed - number(before, "confirmed_events"));
      if (invalid >= number(before, "invalid_records"))
        put(collection, "invalid", invalid - number(before, "invalid_records"));
    }
    put(collection, "source_files",
        uint64_t(json_object_object_length(files.get())));
    uint64_t completed = 0;
    json_object_object_foreach(files.get(), key, value) {
      (void)key;
      auto entry = own(json_object_get(value));
      struct stat st{};
      if (number(entry, "skip_archive") || number(entry, "sealed") ||
          (!lstat(text(entry, "path").c_str(), &st) && S_ISREG(st.st_mode) &&
           !flag(entry, "archive") &&
           static_cast<uint64_t>(st.st_size) == number(entry, "offset")))
        completed++;
    }
    put(collection, "completed_files", completed);
    auto status_envelope =
        parse(read_file(c.state + "/sender-health.json", 65536));
    auto text_payload = text(status_envelope, "payload");
    need(sha(text_payload) == text(status_envelope, "sha256"), STATE);
    auto data = parse(text_payload);
    if (number(data, "time_ms") + 10000 >= captured) {
      put(collection, "success", number(data, "success"));
      put(collection, "error", text(data, "error"));
    }
  } catch (...) {
  }
  put(out, "collection", collection);
  put(out, "health", health);
  put(out, "source_clock_skew_ms", uint64_t(0));
  return out;
}
void telemetry_cycle(const Config &c) {
  if (!c.telemetry.enabled)
    return;
  Fd lock(safe_open(c.state + "/telemetry.lock", O_RDWR | O_CREAT, 0600));
  need(lock.value >= 0, IO);
  if (flock(lock.value, LOCK_EX | LOCK_NB) < 0) {
    need(errno == EWOULDBLOCK || errno == EAGAIN, IO);
    return;
  }
  struct Unlock {
    int fd;
    ~Unlock() { flock(fd, LOCK_UN); }
  } unlock{lock.value};
  J previous;
  std::string state_path = c.state + "/telemetry-state.json";
  struct stat state_stat{};
  if (lstat(state_path.c_str(), &state_stat) == 0)
    previous = parse(read_file(state_path, 8 * 1024 * 1024));
  else
    need(errno == ENOENT, IO);
  uint64_t current = wall_ms();
  if (previous && number(previous, "time") <= current &&
      current - number(previous, "time") < c.telemetry.interval_ms)
    return;
  size_t disk_bytes = 0;
  for (auto &name : children(c.state, 32768))
    if (name.compare(0, 10, "telemetry-") == 0 && name.size() > 6 &&
        name.substr(name.size() - 6) == ".jsonl") {
      struct stat st{};
      need(!lstat(leaf(c.state, name).c_str(), &st) && S_ISREG(st.st_mode), IO);
      disk_bytes += st.st_size;
    }
  auto value = sample(c, previous);
  auto line = dump(value) + "\n";
  need(line.size() <= c.line_bytes, CAPACITY);
  need(disk_bytes + line.size() <= c.telemetry.spool_bytes, CAPACITY);
  std::string active = c.state + "/telemetry-active.jsonl";
  struct stat st{};
  if (!lstat(active.c_str(), &st) &&
      static_cast<uint64_t>(st.st_size) >= c.telemetry.rotate_bytes)
    need(!rename(active.c_str(),
                 (c.state + "/telemetry-" + random_id() + ".jsonl").c_str()),
         IO);
  Fd fd(safe_open(active, O_WRONLY | O_APPEND | O_CREAT, 0600));
  need(fd.value >= 0, IO);
  size_t done = 0;
  while (done < line.size()) {
    ssize_t n = write(fd.value, line.data() + done, line.size() - done);
    need(n > 0, IO);
    done += n;
  }
  need(!fdatasync(fd.value), IO);
  std::string temp = state_path + ".new";
  Fd out(safe_open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0600));
  need(out.value >= 0, IO);
  done = 0;
  while (done < line.size()) {
    ssize_t n = write(out.value, line.data() + done, line.size() - done);
    need(n > 0, IO);
    done += n;
  }
  need(!fdatasync(out.value) && !rename(temp.c_str(), state_path.c_str()), IO);
  Fd dir(safe_open(c.state, O_RDONLY | O_DIRECTORY));
  need(dir.value >= 0 && !fsync(dir.value), IO);
}
} // namespace logs
