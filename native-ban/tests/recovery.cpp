#include "ban.hpp"
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

static int64_t boot_shift, wall_shift;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int __wrap_clock_gettime(clockid_t id, struct timespec *out) {
  int rc = __real_clock_gettime(id, out);
  if (!rc) {
    int64_t shift = id == CLOCK_BOOTTIME   ? boot_shift
                    : id == CLOCK_REALTIME ? wall_shift
                                           : 0;
    int64_t total = (int64_t)out->tv_sec * 1000000000 + out->tv_nsec + shift;
    out->tv_sec = total / 1000000000;
    out->tv_nsec = total % 1000000000;
  }
  return rc;
}
static ban_event event(ban::Engine &e, const char *ip, unsigned seed = 1) {
  ban_event v{};
  v.version = BAN_VERSION;
  v.type = BAN_EVENT;
  v.sequence = 1;
  v.producer[0] = v.request[0] = (uint8_t)seed;
  ban_uuid(e.conf.boot.c_str(), v.boot);
  ban_uuid("00000000-0000-0000-0000-000000000100", v.instance);
  ban_address_parse(ip, &v.ip);
  v.source = BAN_CC;
  v.observed_ns = ban_now();
  v.generation = e.generation;
  std::strcpy(v.scope, "alpha");
  std::strcpy(v.reason, "cc-rule");
  return v;
}
static std::string snapshot(ban::Engine &e, int revision,
                            const char *ip = nullptr) {
  auto j = ban::object(), bans = ban::own(json_object_new_array()),
       fences = ban::own(json_object_new_array()),
       members = ban::own(json_object_new_array());
  ban::set(j, "version", 1);
  ban::set(j, "cluster", e.conf.cluster);
  ban::set(j, "epoch", e.conf.epoch);
  ban::set(j, "revision", std::to_string(revision));
  ban::set(j, "generated", std::to_string(ban::utc()));
  ban::set(j, "allowlist_digest", ban::sha(""));
  ban::set(j, "bans", bans);
  for (auto &member : e.conf.members)
    json_object_array_add(members.get(),
                          json_object_new_string(member.c_str()));
  ban::set(j, "members", members);
  if (ip) {
    auto fence = ban::object();
    ban::set(fence, "ip", std::string(ip));
    ban::set(fence, "time", std::to_string(ban::utc()));
    json_object_array_add(fences.get(), json_object_get(fence.get()));
  }
  ban::set(j, "fences", fences);
  return ban::sign_snapshot(e.conf, ban::dump(j));
}
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  try {
    auto c = ban::config_read(argv[1]);
    std::string mode = argv[2];
    const char *ip = "198.51.100.42";
    if (mode == "remote-fence") {
      ban::Engine e(c);
      e.apply_snapshot(snapshot(e, 1));
      auto queued = event(e, ip);
      std::this_thread::sleep_for(std::chrono::milliseconds(30));
      e.apply_snapshot(snapshot(e, 2, ip));
      ban::require(e.event(queued, c.worker_uid).durable &&
                       !e.record("|" + std::string(ip)),
                   "queued_event_revived_ban");
      std::this_thread::sleep_for(std::chrono::milliseconds(3));
      e.event(event(e, ip, 2), c.worker_uid);
      ban::require((bool)e.record("|" + std::string(ip)),
                   "fresh_event_not_banned");
      e.kernel->detach();
    } else if (mode == "reboot-fence") {
      boot_shift = 30LL * 86400 * 1000000000;
      {
        ban::Engine e(c);
        e.event(event(e, ip), c.worker_uid);
        auto q = ban::object();
        ban::set(q, "operation", std::string("unban"));
        ban::set(q, "ip", std::string(ip));
        ban::set(q, "ban_id",
                 ban::str(e.record("|" + std::string(ip)), "ban_id"));
        e.query(q);
      }
      ban::require(!unlink(c.view_file.c_str()), "fixture_view_reset");
      boot_shift = 0;
      c.boot = "00000000-0000-0000-0000-000000009999";
      ban::Engine e(c);
      e.event(event(e, ip, 2), c.worker_uid);
      ban::require((bool)e.record("|" + std::string(ip)),
                   "old_boot_fence_rejects_new_event");
      e.kernel->detach();
    } else if (mode == "reboot-clock") {
      {
        ban::Engine e(c);
        e.event(event(e, ip), c.worker_uid);
        boot_shift = wall_shift = 5000000000;
        e.tick();
      }
      ban::require(!unlink(c.view_file.c_str()), "fixture_view_reset");
      boot_shift = 0;
      wall_shift = -3600LL * 1000000000;
      c.boot = "00000000-0000-0000-0000-000000009999";
      ban::Engine e(c);
      auto remaining =
          std::stoll(ban::str(e.record("|" + std::string(ip)), "deadline")) -
          (int64_t)ban_now();
      ban::require(remaining > 0 && remaining <= 25000000000LL,
                   "clock_rollback_extends_ban");
      auto installed = e.kernel->entries();
      ban::require(installed.count(ip) && (int64_t)installed.at(ip).deadline -
                                                  (int64_t)ban_now() <=
                                              25000000000LL,
                   "clock_rollback_extends_kernel_ban");
      e.kernel->detach();
    } else if (mode == "quota") {
      std::string id;
      {
        ban::Engine e(c);
        e.event(event(e, ip), c.worker_uid);
        id = ban::str(e.record("|" + std::string(ip)), "ban_id");
        auto request = ban::object();
        ban::set(request, "operation", std::string("checkpoint"));
        auto checkpoints = e.db.stats().checkpoints;
        e.query(request);
        ban::require(e.db.stats().checkpoints == checkpoints + 1,
                     "manual_checkpoint_missing");
        auto next = c;
        next.storage.max_entries += 1024;
        bool rejected = false;
        try {
          e.reload(next);
        } catch (const std::exception &x) {
          rejected = std::string(x.what()) == "storage_options_require_restart";
        }
        ban::require(rejected, "quota_hot_reload_not_rejected");
      }
      c.storage.max_entries += 1024;
      ban::Engine e(c);
      ban::require(ban::str(e.record("|" + std::string(ip)), "ban_id") == id,
                   "quota_restart_changed_state");
      e.kernel->detach();
    } else if (mode == "projection") {
      auto held = c.ip_log + ".fixture-hold";
      {
        ban::Engine e(c);
        ban::require(!rename(c.ip_log.c_str(), held.c_str()) &&
                         !mkdir(c.ip_log.c_str(), 0700),
                     "fixture_log_block");
        e.db.begin();
        for (unsigned i = 0; i < 2; i++) {
          auto r = ban::object();
          ban::set(r, "ip", std::string(ip));
          e.audit("PARTIAL_PROJECTION", r);
        }
        e.db.commit();
        bool rejected = false;
        try {
          e.project();
        } catch (...) {
          rejected = true;
        }
        ban::require(rejected && !e.logs_ok, "second_log_failure_missing");
      }
      ban::require(!rmdir(c.ip_log.c_str()) &&
                       !rename(held.c_str(), c.ip_log.c_str()),
                   "fixture_log_restore");
      ban::Engine e(c);
      for (auto path : {c.event_log, c.ip_log}) {
        std::ifstream in(path);
        std::string line;
        std::set<std::string> sequences;
        unsigned rows = 0;
        while (std::getline(in, line)) {
          auto r = ban::parse(line);
          ban::require(sequences.insert(ban::str(r, "seq")).second,
                       "duplicate_projection_sequence");
          rows++;
        }
        ban::require(rows == 2, "missing_projection_rows");
      }
      ban::require(e.logs_ok, "recovered_projection_not_durable");
      e.kernel->detach();
    } else if (mode == "batch") {
      ban::Engine e(c);
      std::vector<std::pair<ban_event, uint32_t>> batch;
      for (unsigned i = 0; i < 64; i++)
        batch.push_back(
            {event(e, ("198.51.100." + std::to_string(i + 1)).c_str(), i + 1),
             c.worker_uid});
      auto invalid = event(e, "203.0.113.90", 100);
      strcpy(invalid.reason, "not-trusted");
      batch.push_back({invalid, c.worker_uid});
      auto syncs = e.db.stats().syncs;
      auto acks = e.events(batch);
      ban::require(acks.size() == 65 && !acks.back(), "invalid_batch_item");
      for (unsigned i = 0; i < 64; i++)
        ban::require(acks[i] && acks[i]->durable && acks[i]->result == 0,
                     "batch_durable_receipt");
      ban::require(e.count("records") == 64 && e.db.stats().syncs - syncs <= 3,
                   "group_commit_not_batched");
      ban::require(e.kernel->entries().size() == 64,
                   "batch_kernel_application");
      e.kernel->detach();
    } else if (mode == "backlog") {
      {
        ban::Engine e(c);
        e.db.begin();
        for (int i = 0; i < 800; i++) {
          auto j = ban::object();
          ban::set(j, "ip", std::string(ip));
          e.audit("BACKLOG_FIXTURE", j);
        }
        e.db.commit();
      }
      ban::Engine e(c);
      ban::require(e.logs_ok, "recoverable_log_backlog_blocks_startup");
      for (auto path : {c.event_log, c.ip_log})
        ban::require(std::stoll(e.meta("log_cursor:" + path)) ==
                         (int64_t)e.audit_sequence(),
                     "incomplete_log_projection");
      e.kernel->detach();
    } else
      return 2;
    std::cout << "PASS " << mode << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
