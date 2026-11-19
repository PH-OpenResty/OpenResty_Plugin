#include "../bpf/packet.h"
#include "log_sync.hpp"
#include <arpa/inet.h>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
static volatile sig_atomic_t stopped;
static void stop(int) { stopped = 1; }
static int quiet(enum libbpf_print_level, const char *, va_list) { return 0; }
int main(int argc, char **argv) {
  using namespace logs;
  if (argc != 3 || strcmp(argv[1], "--config")) {
    std::cerr << "usage: scdn-log-netmon --config /absolute/config.json\n";
    return 2;
  }
  try {
    libbpf_set_print(quiet);
    auto config = parse(read_file(argv[2], 65536));
    auto output = text(config, "output"), object = text(config, "bpf_object");
    absolute(output);
    absolute(object);
    auto interfaces = get(config, "interfaces"),
         port_list = get(config, "ports");
    need(json_object_array_length(interfaces.get()) >= 1 &&
             json_object_array_length(interfaces.get()) <= 32 &&
             json_object_array_length(port_list.get()) >= 1 &&
             json_object_array_length(port_list.get()) <= 256,
         CONFIG);
    unsigned interval = number(config, "interval_ms", 1000);
    need(interval >= 100 && interval <= 60000, CONFIG);
    auto *raw = bpf_object__open_file(object.c_str(), nullptr);
    need(raw && !libbpf_get_error(raw), IO);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> owner(
        raw, bpf_object__close);
    need(!bpf_object__load(raw), IO);
    int map = bpf_object__find_map_fd_by_name(raw, "ports"),
        counts = bpf_object__find_map_fd_by_name(raw, "packets");
    auto *program = bpf_object__find_program_by_name(raw, "count_packets");
    need(map >= 0 && counts >= 0 && program, IO);
    for (size_t i = 0; i < json_object_array_length(port_list.get()); i++) {
      auto n =
          json_object_get_uint64(json_object_array_get_idx(port_list.get(), i));
      need(n > 0 && n <= 65535, CONFIG);
      uint16_t port = n;
      uint8_t value = 1;
      need(!bpf_map_update_elem(map, &port, &value, BPF_ANY), IO);
    }
    std::vector<std::unique_ptr<Fd>> sockets;
    for (size_t i = 0; i < json_object_array_length(interfaces.get()); i++) {
      std::string name = str(
          own(json_object_get(json_object_array_get_idx(interfaces.get(), i))));
      unsigned index = if_nametoindex(name.c_str());
      need(index > 0, CONFIG);
      auto fd = std::make_unique<Fd>(
          socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL)));
      need(fd->value >= 0, IO);
      sockaddr_ll bind_to{};
      bind_to.sll_family = AF_PACKET;
      bind_to.sll_protocol = htons(ETH_P_ALL);
      bind_to.sll_ifindex = index;
      need(!bind(fd->value, reinterpret_cast<sockaddr *>(&bind_to),
                 sizeof(bind_to)),
           IO);
      int program_fd = bpf_program__fd(program);
      need(!setsockopt(fd->value, SOL_SOCKET, SO_ATTACH_BPF, &program_fd,
                       sizeof(program_fd)),
           IO);
      sockets.push_back(std::move(fd));
    }
    int cpus = libbpf_num_possible_cpus();
    need(cpus > 0 && cpus <= 8192, STATE);
    auto session = random_id();
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    while (!stopped) {
      auto row = obj();
      put(row, "session", session);
      put(row, "scope", "configured_interfaces_and_listener_ports");
      put(row, "node", text(config, "node"));
      put(row, "interfaces", interfaces);
      put(row, "ports", port_list);
      auto pid_file = text(config, "nginx_pid_file"),
           ban_socket = text(config, "ban_socket"),
           ban_map = text(config, "ban_counter_map");
      if (!pid_file.empty() || !ban_socket.empty() || !ban_map.empty()) {
        Config privileged;
        privileged.node = text(config, "node");
        privileged.state = output.substr(0, output.rfind('/'));
        privileged.telemetry.pid_file = pid_file;
        privileged.telemetry.ban_socket = ban_socket;
        privileged.telemetry.ban_counter_map = ban_map;
        for (auto &path : {pid_file, ban_socket, ban_map})
          if (!path.empty())
            absolute(path);
        auto value = sample(privileged, {}), safe = obj();
        for (auto key : {"connections", "ban_ready", "active_bans",
                         "ban_records", "kernel_drop_counter", "health"}) {
          if (!strcmp(key, "connections") && pid_file.empty())
            continue;
          json_object *v = nullptr;
          if (json_object_object_get_ex(value.get(), key, &v) && v)
            put(safe, key, own(json_object_get(v)));
        }
        put(row, "privileged_sample", safe);
      }
      uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
      put(row, "time_ms", ms);
      for (uint32_t direction = 0; direction < 2; direction++) {
        std::vector<scdn_packet_counts> values(cpus);
        need(!bpf_map_lookup_elem(counts, &direction, values.data()), IO);
        std::array<uint64_t, 10> total{};
        for (auto &value : values) {
          std::array<uint64_t, 10> row{};
          static_assert(sizeof(row) == sizeof(value), "counter ABI");
          memcpy(row.data(), &value, sizeof(value));
          for (unsigned n = 0; n < 10; n++)
            total[n] += row[n];
        }
        auto counters = obj();
        const char *names[] = {"tcp_packets", "tcp_bytes",   "tcp_ack",
                               "tcp_syn",     "tcp_syn_ack", "tcp_syn_only",
                               "tcp_fin",     "tcp_rst",     "udp_packets",
                               "udp_bytes"};
        for (unsigned n = 0; n < 10; n++)
          put(counters, names[n], total[n]);
        put(row, direction ? "egress" : "ingress", counters);
      }
      auto data = dump(row) + "\n";
      Fd fd(safe_open(output + ".new", O_WRONLY | O_CREAT | O_TRUNC, 0640));
      need(fd.value >= 0, IO);
      size_t at = 0;
      while (at < data.size()) {
        ssize_t n = write(fd.value, data.data() + at, data.size() - at);
        need(n > 0, IO);
        at += n;
      }
      need(!fdatasync(fd.value) &&
               !rename((output + ".new").c_str(), output.c_str()),
           IO);
      for (unsigned elapsed = 0; elapsed < interval && !stopped; elapsed += 50)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
  } catch (const Failure &e) {
    std::cerr << scdn_log_sync_error(e.code) << "\n";
    return e.code;
  } catch (...) {
    std::cerr << "internal\n";
    return 3;
  }
}
