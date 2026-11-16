#include "ban.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
namespace ban {
static std::vector<J> array(const J &j) {
  require(json_object_is_type(j.get(), json_type_array), "array_required");
  std::vector<J> out;
  for (size_t i = 0; i < json_object_array_length(j.get()); i++)
    out.push_back(own(json_object_get(json_object_array_get_idx(j.get(), i))));
  return out;
}
static std::string item_string(const J &j) {
  require(json_object_is_type(j.get(), json_type_string),
          "string_item_required");
  auto s = std::string(json_object_get_string(j.get()));
  require(s.size() == (size_t)json_object_get_string_len(j.get()),
          "nul_string");
  return s;
}
static std::string path(const J &j, const char *k) {
  auto s = str(j, k);
  require(s.size() > 1 && s.size() < 1024 && s[0] == '/' && s.back() != '/' &&
              s.find("..") == std::string::npos,
          "absolute_path_required");
  return s;
}
static int64_t bounded(const J &j, const char *k, int64_t lo, int64_t hi) {
  auto n = num(j, k);
  require(n >= lo && n <= hi, std::string("out_of_range_") + k);
  return n;
}
Config config_read(const std::string &file) {
  Config c;
  c.json = parse(read_file(file, 131072, true));
  auto j = c.json;
  keys(j, "version node_id runtime_dir state_dir event_socket admin_socket "
          "event_log ip_log worker_uid worker_gid sync_uid instances "
          "trusted_rules policy datapath services allowlist cluster storage");
  require(num(j, "version") == 1, "config_version");
  c.node = str(j, "node_id");
  require(id_valid(c.node), "node_id");
  c.boot = boot_id();
  c.runtime = path(j, "runtime_dir");
  c.state = path(j, "state_dir");
  c.storage.directory = c.state;
  json_object *storage = nullptr;
  if (json_object_object_get_ex(j.get(), "storage", &storage)) {
    auto s = own(json_object_get(storage));
    keys(s, "mode max_entries max_memory_mb checkpoint_mb");
    auto mode = str(s, "mode");
    require(mode == "persistent" || mode == "memory", "storage_mode");
    c.storage.persistent = mode == "persistent";
    json_object *option = nullptr;
    if (json_object_object_get_ex(s.get(), "max_entries", &option))
      c.storage.max_entries =
          (size_t)bounded(s, "max_entries", 65536, 16000000);
    if (json_object_object_get_ex(s.get(), "max_memory_mb", &option))
      c.storage.max_bytes =
          (size_t)bounded(s, "max_memory_mb", 16, 4096) * 1024 * 1024;
    if (json_object_object_get_ex(s.get(), "checkpoint_mb", &option))
      c.storage.checkpoint_bytes =
          (size_t)bounded(s, "checkpoint_mb", 1, 1024) * 1024 * 1024;
    c.storage.max_log_bytes =
        std::max<size_t>(2ull * 1024 * 1024 * 1024, c.storage.max_bytes * 4);
  }
  c.event_socket = path(j, "event_socket");
  c.admin_socket = path(j, "admin_socket");
  c.event_log = path(j, "event_log");
  c.ip_log = path(j, "ip_log");
  c.view_file = c.runtime + "/view";
  require(c.event_log != c.ip_log && c.event_socket != c.admin_socket &&
              c.runtime != c.state,
          "distinct_paths_required");
  c.worker_uid = (uint32_t)bounded(j, "worker_uid", 1, 4294967294);
  c.worker_gid = (uint32_t)bounded(j, "worker_gid", 1, 4294967294);
  c.sync_uid = (uint32_t)bounded(j, "sync_uid", 1, 4294967294);
  for (auto v : array(get(j, "instances"))) {
    auto s = item_string(v);
    uint8_t id[16];
    require(ban_uuid(s.c_str(), id) && c.instances.insert(hex(id, 16)).second,
            "instance_id");
  }
  require(!c.instances.empty() && c.instances.size() <= 32, "instance_limit");
  for (auto v : array(get(j, "trusted_rules"))) {
    keys(v, "source reason");
    auto source = str(v, "source"), reason = str(v, "reason");
    require((source == "waf" || source == "cc") && reason_valid(reason),
            "trusted_rule");
    require(c.rules.insert(source + ":" + reason).second, "duplicate_rule");
  }
  require(!c.rules.empty() && c.rules.size() <= 4096, "rule_limit");
  auto p = get(j, "policy");
  keys(p,
       "l7_seconds l3_seconds window_ms threshold event_age_ms renew_on_hit");
  c.l7 = bounded(p, "l7_seconds", 1, 2592000);
  c.l3 = bounded(p, "l3_seconds", 1, 2592000);
  c.window = bounded(p, "window_ms", 100, 3600000);
  c.threshold = bounded(p, "threshold", 2, 1024);
  c.event_age = bounded(p, "event_age_ms", 1, 10000);
  require(c.event_age <= c.window, "event_age_window");
  auto renew = get(p, "renew_on_hit");
  require(json_object_is_type(renew.get(), json_type_boolean) &&
              !json_object_get_boolean(renew.get()),
          "fixed_expiry_required");
  p = get(j, "datapath");
  keys(p, "mode interfaces object_file pin_root");
  c.mode = str(p, "mode");
  require(c.mode == "xdp_native" || c.mode == "tcx_ingress", "datapath_mode");
  c.object_file = path(p, "object_file");
  c.pin = path(p, "pin_root");
  for (auto v : array(get(p, "interfaces"))) {
    auto s = item_string(v);
    require(!s.empty() && s.size() <= 15 &&
                s.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
                                    "QRSTUVWXYZ0123456789_.-") ==
                    std::string::npos,
            "interface");
    require(std::find(c.interfaces.begin(), c.interfaces.end(), s) ==
                c.interfaces.end(),
            "duplicate_interface");
    c.interfaces.push_back(s);
  }
  require(!c.interfaces.empty() && c.interfaces.size() <= 16,
          "interface_limit");
  for (auto v : array(get(j, "services"))) {
    keys(v, "ip protocol port");
    ban_service service{};
    service.ip = ip_parse(str(v, "ip"));
    auto protocol = str(v, "protocol");
    require(protocol == "tcp" || protocol == "udp", "service_protocol");
    service.protocol = protocol == "tcp" ? 6 : 17;
    service.port = htons((uint16_t)bounded(v, "port", 1, 65535));
    for (auto &old : c.services)
      require(memcmp(&old, &service, sizeof(service)), "duplicate_service");
    c.services.push_back(service);
  }
  require(!c.services.empty() && c.services.size() <= 1024, "service_limit");
  for (auto v : array(get(j, "allowlist"))) {
    auto s = item_string(v);
    auto slash = s.find('/');
    require(slash != std::string::npos, "cidr_required");
    auto a = ip_parse(s.substr(0, slash));
    auto bits = s.substr(slash + 1);
    require(!bits.empty() &&
                bits.find_first_not_of("0123456789") == std::string::npos &&
                bits.size() <= 3,
            "cidr_bits");
    auto n = std::stoi(bits);
    require(n >= 0 && n <= (a.family == 4 ? 32 : 128), "cidr_bits");
    c.exemptions.push_back(s);
  }
  require(c.exemptions.size() <= 4096, "allowlist_limit");
  p = get(j, "cluster");
  keys(p, "role cluster_id authority_epoch master_url ca certificate key "
          "signing_key verify_key socket members poll_ms clock_uncertainty_ms");
  c.role = str(p, "role");
  require(c.role == "master" || c.role == "node", "cluster_role");
  require(c.role != "master" || c.storage.persistent,
          "authority_requires_persistent_storage");
  c.cluster = str(p, "cluster_id");
  c.epoch = str(p, "authority_epoch");
  uint8_t id[16];
  require(ban_uuid(c.cluster.c_str(), id) && ban_uuid(c.epoch.c_str(), id),
          "cluster_identity");
  c.cluster_socket = path(p, "socket");
  require(c.cluster_socket != c.event_socket &&
              c.cluster_socket != c.admin_socket,
          "distinct_socket");
  c.sign = str(p, "signing_key");
  c.verify = path(p, "verify_key");
  c.master_url = str(p, "master_url");
  c.ca = str(p, "ca");
  c.cert = str(p, "certificate");
  c.key = str(p, "key");
  c.poll_ms = bounded(p, "poll_ms", 100, 60000);
  c.skew_ms = bounded(p, "clock_uncertainty_ms", 0, 5000);
  for (auto v : array(get(p, "members"))) {
    auto s = item_string(v);
    require(id_valid(s) && c.members.insert(s).second, "member_id");
  }
  require(c.members.count(c.node) && c.members.size() <= 1024, "membership");
  if (c.role == "master") {
    require(!c.sign.empty() && c.sign[0] == '/', "signing_key");
    require(c.master_url.empty(), "master_url_on_authority");
  } else {
    require(c.sign.empty() && c.master_url.rfind("https://", 0) == 0 &&
                c.master_url.find_first_of("?#@", 8) == std::string::npos &&
                c.master_url.find('/', 8) == std::string::npos,
            "master_url");
    require(!c.ca.empty() && !c.cert.empty() && !c.key.empty() &&
                c.ca[0] == '/' && c.cert[0] == '/' && c.key[0] == '/',
            "mtls_paths");
  }
  auto immutable = parse(dump(j));
  json_object_object_del(immutable.get(), "policy");
  json_object_object_del(immutable.get(), "storage");
  auto ownership = object();
  set(ownership, "mode",
      std::string(c.storage.persistent ? "persistent" : "memory"));
  set(immutable, "storage", ownership);
  c.immutable = dump(immutable);
  return c;
}
bool exempt(const Config &c, const ban_address &a) {
  for (const auto &s : c.exemptions) {
    auto slash = s.find('/');
    auto network = ip_parse(s.substr(0, slash));
    if (network.family != a.family)
      continue;
    unsigned bits = (unsigned)std::stoi(s.substr(slash + 1)),
             start = a.family == 4 ? 12 : 0;
    bool match = true;
    for (unsigned i = 0; i < bits; i++)
      if ((network.address[start + i / 8] & (1 << (7 - i % 8))) !=
          (a.address[start + i / 8] & (1 << (7 - i % 8)))) {
        match = false;
        break;
      }
    if (match)
      return true;
  }
  return false;
}
} // namespace ban
