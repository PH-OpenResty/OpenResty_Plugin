#ifndef SCDN_BAN_AGENT_HPP
#define SCDN_BAN_AGENT_HPP
#include "ban_common.h"
#include <array>
#include <atomic>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <functional>
#include <json-c/json.h>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <set>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <vector>
namespace ban {
using J = std::shared_ptr<json_object>;
inline J own(json_object *p) { return J(p, json_object_put); }
J object();
J parse(const std::string &s);
std::string dump(const J &j);
J get(const J &j, const char *key);
std::string str(const J &j, const char *key);
int64_t num(const J &j, const char *key);
void set(J &j, const char *key, const std::string &v);
void set(J &j, const char *key, int64_t v);
void set(J &j, const char *key, const J &v);
void keys(const J &j, const std::string &allowed);
void require(bool condition, const std::string &error);
std::string hex(const void *p, size_t n);
std::string random_id();
std::string sha(const std::string &s);
std::string read_file(const std::string &path, size_t max, bool secret = false);
void atomic_file(const std::string &path, const std::string &bytes);
int safe_open(const std::string &path, int flags, mode_t mode = 0600);
int64_t utc();
std::string boot_id();
std::string ip_text(const ban_address &a);
ban_address ip_parse(const std::string &s);
bool id_valid(const std::string &s);
bool reason_valid(const std::string &s);
struct Config {
  J json;
  std::string node, boot, runtime, state, event_socket, admin_socket, view_file,
      event_log, ip_log;
  uint32_t worker_uid, worker_gid, sync_uid;
  std::set<std::string> instances, rules;
  int64_t l7, l3, window, threshold, event_age;
  std::vector<std::string> exemptions;
  std::string mode, object_file, pin;
  std::vector<std::string> interfaces;
  std::vector<ban_service> services;
  std::string role, cluster, epoch, master_url, ca, cert, key, sign, verify,
      cluster_socket;
  std::set<std::string> members;
  int64_t poll_ms, skew_ms;
  std::string immutable;
};
Config config_read(const std::string &path);
bool exempt(const Config &conf, const ban_address &address);
struct Statement {
  sqlite3_stmt *p = nullptr;
  Statement(sqlite3 *d, const char *sql);
  ~Statement();
  void bind(int index, const std::string &v);
  void bind(int index, int64_t v);
  bool row();
  void done();
  std::string text(int col);
  int64_t integer(int col);
};
struct Kernel {
  bpf_object *object = nullptr;
  std::vector<bpf_link *> links;
  std::vector<int> pinned_links;
  std::vector<std::string> link_paths;
  int bans = -1;
  std::string pin;
  bool ready = false;
  explicit Kernel(const Config &conf);
  ~Kernel();
  void put(const ban_address &a, const ban_kernel_value &v);
  void remove(const ban_address &a);
  uint64_t watermark();
  void watermark(uint64_t value);
  std::map<std::string, ban_kernel_value> entries();
  void detach();
};
struct View {
  int fd = -1, readonly = -1;
  ban_view *data = nullptr;
  explicit View(const Config &conf);
  ~View();
  void publish(const ban_record &r, bool remove = false);
};
struct Engine {
  Config conf;
  sqlite3 *db = nullptr;
  std::unique_ptr<Kernel> kernel;
  std::unique_ptr<View> view;
  std::mutex mutex;
  uint64_t generation = 1;
  std::string sync_error;
  std::string policy_error;
  bool stopping = false;
  int64_t accepted_revision = 0;
  bool logs_ok = true;
  bool enforcement_pending = true;
  explicit Engine(Config c);
  ~Engine();
  void sql(const char *s);
  std::string meta(const std::string &key, const std::string &fallback = "");
  void meta_set(const std::string &key, const std::string &value);
  void audit(const std::string &action, const J &record);
  void project();
  void reconcile();
  void tick();
  ban_ack event(const ban_event &e, uint32_t uid);
  J query(const J &request);
  J status();
  J bridge(const std::string &node, const std::string &operation,
           const J &request);
  J proposal(const std::string &node, const J &request);
  J snapshot();
  void apply_snapshot(const std::string &signed_json);
  void publish_snapshot();
  void cluster_cycle();
  void reload(const Config &next);
  void insert_ban(const ban_event &e, int layer);
  void delete_ban(const std::string &key, const std::string &action);
  int64_t count(const char *table);
  J record(const std::string &key);
  void save_record(const std::string &key, const J &r);
};
std::string sign_snapshot(const Config &conf, const std::string &payload);
std::string verify_snapshot(const Config &conf, const std::string &envelope);
std::pair<int, std::string> http(const Config &conf, const std::string &path,
                                 const std::string &body);
void serve(Engine &engine, std::atomic<bool> &stop, std::atomic<bool> &reload,
           const std::string &path);
} // namespace ban
#endif
