#include "ban.hpp"
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>
#include <unistd.h>

static int64_t boot_shift, wall_shift;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int __wrap_clock_gettime(clockid_t id, struct timespec *out) {
  int rc = __real_clock_gettime(id, out);
  if (!rc) {
    int64_t shift = id == CLOCK_BOOTTIME ? boot_shift : id == CLOCK_REALTIME ? wall_shift : 0;
    int64_t total = (int64_t)out->tv_sec * 1000000000 + out->tv_nsec + shift;
    out->tv_sec = total / 1000000000; out->tv_nsec = total % 1000000000;
  }
  return rc;
}
static ban_event event(ban::Engine &e, const char *ip, unsigned seed = 1) {
  ban_event v{};
  v.version = BAN_VERSION; v.type = BAN_EVENT; v.sequence = 1;
  v.producer[0] = v.request[0] = (uint8_t)seed;
  ban_uuid(e.conf.boot.c_str(), v.boot);
  ban_uuid("00000000-0000-0000-0000-000000000100", v.instance);
  ban_address_parse(ip, &v.ip); v.source = BAN_CC;
  v.observed_ns = ban_now(); v.generation = e.generation;
  std::strcpy(v.scope, "alpha"); std::strcpy(v.reason, "cc-rule");
  return v;
}
static std::string snapshot(ban::Engine &e, int revision, const char *ip = nullptr) {
  auto j = ban::object(), bans = ban::own(json_object_new_array()),
       fences = ban::own(json_object_new_array()), members = ban::own(json_object_new_array());
  ban::set(j, "version", 1); ban::set(j, "cluster", e.conf.cluster); ban::set(j, "epoch", e.conf.epoch);
  ban::set(j, "revision", std::to_string(revision)); ban::set(j, "generated", std::to_string(ban::utc()));
  ban::set(j, "allowlist_digest", ban::sha("")); ban::set(j, "bans", bans);
  for (auto &member : e.conf.members) json_object_array_add(members.get(), json_object_new_string(member.c_str()));
  ban::set(j, "members", members);
  if (ip) {
    auto fence = ban::object(); ban::set(fence, "ip", std::string(ip));
    ban::set(fence, "time", std::to_string(ban::utc()));
    json_object_array_add(fences.get(), json_object_get(fence.get()));
  }
  ban::set(j, "fences", fences);
  return ban::sign_snapshot(e.conf, ban::dump(j));
}
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  try {
    auto c = ban::config_read(argv[1]); std::string mode = argv[2];
    const char *ip = "198.51.100.42";
    if (mode == "remote-fence") {
      ban::Engine e(c); e.apply_snapshot(snapshot(e, 1));
      auto queued = event(e, ip);
      std::this_thread::sleep_for(std::chrono::milliseconds(30));
      e.apply_snapshot(snapshot(e, 2, ip));
      ban::require(e.event(queued, c.worker_uid).durable && !e.record("|" + std::string(ip)), "queued_event_revived_ban");
      std::this_thread::sleep_for(std::chrono::milliseconds(3));
      e.event(event(e, ip, 2), c.worker_uid);
      ban::require((bool)e.record("|" + std::string(ip)), "fresh_event_not_banned");
      e.kernel->detach();
    } else if (mode == "reboot-fence") {
      boot_shift = 30LL * 86400 * 1000000000;
      { ban::Engine e(c); e.event(event(e, ip), c.worker_uid);
        auto q = ban::object(); ban::set(q, "operation", std::string("unban"));
        ban::set(q, "ip", std::string(ip)); ban::set(q, "ban_id", ban::str(e.record("|" + std::string(ip)), "ban_id"));
        e.query(q); }
      ban::require(!unlink(c.view_file.c_str()), "fixture_view_reset");
      boot_shift = 0; c.boot = "00000000-0000-0000-0000-000000009999";
      ban::Engine e(c); e.event(event(e, ip, 2), c.worker_uid);
      ban::require((bool)e.record("|" + std::string(ip)), "old_boot_fence_rejects_new_event");
      e.kernel->detach();
    } else if (mode == "reboot-clock") {
      { ban::Engine e(c); e.event(event(e, ip), c.worker_uid);
        boot_shift = wall_shift = 5000000000; e.tick(); }
      ban::require(!unlink(c.view_file.c_str()), "fixture_view_reset");
      boot_shift = 0; wall_shift = -3600LL * 1000000000;
      c.boot = "00000000-0000-0000-0000-000000009999";
      ban::Engine e(c);
      auto remaining = std::stoll(ban::str(e.record("|" + std::string(ip)), "deadline")) - (int64_t)ban_now();
      ban::require(remaining > 0 && remaining <= 25000000000LL, "clock_rollback_extends_ban");
      auto installed = e.kernel->entries();
      ban::require(installed.count(ip) && (int64_t)installed.at(ip).deadline - (int64_t)ban_now() <= 25000000000LL,
                   "clock_rollback_extends_kernel_ban");
      e.kernel->detach();
    } else if (mode == "backlog") {
      { ban::Engine e(c); e.sql("BEGIN IMMEDIATE");
        for (int i = 0; i < 800; i++) { auto j = ban::object(); ban::set(j, "ip", std::string(ip)); e.audit("BACKLOG_FIXTURE", j); }
        e.sql("COMMIT"); }
      ban::Engine e(c); ban::require(e.logs_ok, "recoverable_log_backlog_blocks_startup");
      for (auto path : {c.event_log, c.ip_log})
        ban::require(std::stoll(e.meta("log_cursor:" + path)) == e.count("audit"), "incomplete_log_projection");
      e.kernel->detach();
    } else return 2;
    std::cout << "PASS " << mode << std::endl;
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; return 1; }
}
