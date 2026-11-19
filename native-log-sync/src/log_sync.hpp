#pragma once
#include "scdn_log_sync.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <curl/curl.h>
#include <json-c/json.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <zlib.h>

namespace logs {
enum Code {
  OK,
  CONFIG,
  IO,
  STATE,
  CAPACITY,
  SOURCE,
  TRANSPORT,
  BACKEND,
  LOCKED
};
struct Failure : std::runtime_error {
  int code;
  explicit Failure(int c) : std::runtime_error("log_sync_failure"), code(c) {}
};
inline void need(bool ok, int code) {
  if (!ok)
    throw Failure(code);
}
using J = std::shared_ptr<json_object>;
inline J own(json_object *p) {
  need(p != nullptr, STATE);
  return J(p, json_object_put);
}
inline J obj() { return own(json_object_new_object()); }
inline J arr() { return own(json_object_new_array()); }
J parse(const std::string &text);
std::string dump(const J &j);
J copy(const J &j);
J get(const J &j, const char *key, bool required = true);
std::string str(const J &j);
std::string text(const J &j, const char *key, const std::string &fallback = "");
uint64_t number(const J &j, const char *key, uint64_t fallback = 0);
bool flag(const J &j, const char *key, bool fallback = false);
void put(const J &j, const char *key, const std::string &value);
void put(const J &j, const char *key, uint64_t value);
void put(const J &j, const char *key, const J &value);
std::string sha(const std::string &value);
std::string random_id();
std::string now();
std::string base64(const std::string &raw);
bool utf8(const std::string &raw);
int safe_open(const std::string &path, int flags, unsigned mode = 0);
std::string read_file(const std::string &path, size_t limit,
                      bool secret = false);
void absolute(const std::string &path);
struct Fd {
  int value = -1;
  Fd() = default;
  explicit Fd(int v) : value(v) {}
  ~Fd();
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
};
struct Source {
  std::string id, start, format, kind;
  std::vector<std::string> paths;
};
struct Sink {
  std::string id, type, endpoint, index, database, table;
  std::string authorization_file, username_file, password_file, ca_file;
};
struct StatusSource {
  std::string id, url, socket, path, format, authorization_file;
};
struct Telemetry {
  bool enabled = false;
  unsigned interval_ms = 1000;
  size_t spool_bytes = 256 * 1024 * 1024, rotate_bytes = 8 * 1024 * 1024;
  std::string proc_root = "/proc", pid_file, cache_path, sites_file,
              packet_file, ban_socket, ban_counter_map;
  std::vector<StatusSource> endpoints;
};
struct Config {
  std::string state, node, binding;
  std::vector<Source> sources;
  std::vector<Sink> sinks;
  size_t batch_records = 512, batch_bytes = 4 * 1024 * 1024, line_bytes = 65536;
  size_t max_files = 4096, response_bytes = 4 * 1024 * 1024;
  unsigned timeout_ms = 10000, connect_ms = 2000, retry_ms = 1000;
  Telemetry telemetry;
  const std::atomic<bool> *stop = nullptr;
};
Config config_read(const std::string &path);
struct Input {
  std::string key, path, source;
  int fd = -1;
  gzFile gz = nullptr;
  bool archive = false;
  uint64_t pos = 0;
  uint64_t cache_offset = 0;
  std::string cache;
  ~Input();
  std::string at(uint64_t offset, size_t count);
};
J sample(const Config &conf, J previous);
J site_catalog(const std::string &path);
void telemetry_cycle(const Config &conf);
J normalize(const Config &conf, const Source &source, const J &fields,
            const std::string &fallback);
bool internal_ip(const std::string &ip, unsigned &family);
std::string fetch_status(const Config &conf, const StatusSource &source);
struct Engine {
  Config conf;
  Fd directory, lock;
  std::map<std::string, std::shared_ptr<Input>> inputs;
  uint64_t retry_at = 0;
  explicit Engine(const std::string &path);
  J load(const char *name, bool optional);
  void save(const char *name, const J &payload);
  void erase(const char *name);
  J prepare(J state, scdn_log_sync_result &result);
  bool deliver(const J &pending, scdn_log_sync_result &result);
  int cycle(scdn_log_sync_result &result);
};
bool send(const Config &conf, const Sink &sink, const J &events,
          const std::string &batch);
uint64_t monotonic_ms();
} // namespace logs
