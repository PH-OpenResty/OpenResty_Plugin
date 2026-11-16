#include "ban.hpp"
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
namespace ban {
static std::string scalar(int64_t n) { return std::to_string(n); }
static int64_t integer_text(const J &j, const char *k) {
  auto s = str(j, k);
  require(!s.empty() && s.size() <= 19 &&
              s.find_first_not_of("0123456789") == std::string::npos,
          "integer_string");
  try {
    return std::stoll(s);
  } catch (...) {
    throw std::runtime_error("integer_overflow");
  }
}
static std::string address_key(const std::string &ip,
                               const std::string &scope) {
  return scope + "|" + ip;
}
static ban_store::Options storage_options(const Config &c) {
  struct stat st{};
  for (const char *name :
       {"state.sqlite", "state.sqlite-wal", "state.sqlite-shm"}) {
    auto file = c.state + "/" + name;
    require(lstat(file.c_str(), &st) != 0 && errno == ENOENT,
            "legacy_state_requires_offline_migration");
  }
  return c.storage;
}
std::string Engine::meta(const std::string &key, const std::string &fallback) {
  auto value = db.get(Table::Meta, key);
  return value ? *value : fallback;
}
void Engine::meta_set(const std::string &key, const std::string &value) {
  db.put(Table::Meta, key, value);
}
int64_t Engine::count(const char *name) {
  return (int64_t)db.size(ban_store::table(name));
}
J Engine::data(Table t, const std::string &key) {
  auto value = db.get(t, key);
  return value ? parse(*value) : J{};
}
void Engine::save(Table t, const std::string &key, const J &value) {
  db.put(t, key, dump(value));
}
uint64_t Engine::audit_sequence() {
  return std::stoull(meta("audit_seq", "0"));
}
uint64_t Engine::producer_sequence(const std::string &id) {
  auto value = db.get(Table::Producers, id);
  return value ? std::stoull(*value) : 0;
}
static void volatile_log_session(const std::string &path) {
  struct stat st{};
  if (lstat(path.c_str(), &st)) {
    require(errno == ENOENT, "log_lstat");
    return;
  }
  require(S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
              !(st.st_mode & 007),
          "log_permissions");
  auto split = path.rfind('/');
  auto name = path.substr(split + 1);
  auto archived = name + ".session-" + random_id() + ".jsonl";
  int dir = safe_open(path.substr(0, split), O_RDONLY | O_DIRECTORY);
  require(dir >= 0, "log_directory");
  bool ok = !renameat(dir, name.c_str(), dir, archived.c_str()) && !fsync(dir);
  close(dir);
  require(ok, "log_session_rotate");
}
Engine::Engine(Config c) : conf(std::move(c)), db(storage_options(conf)) {
  db.begin();
  try {
    require(meta("version", "1") == "1", "state_version");
    if (meta("node").empty()) {
      meta_set("node", conf.node);
      meta_set("cluster", conf.cluster);
      meta_set("epoch", conf.epoch);
      meta_set("revision", "1");
      meta_set("local_seq", "0");
      meta_set("policy", "1");
      meta_set("version", "1");
      meta_set("immutable", conf.immutable);
    }
    require(meta("node") == conf.node && meta("cluster") == conf.cluster &&
                meta("epoch") == conf.epoch,
            "state_identity_mismatch");
    require(meta("immutable") == conf.immutable,
            "immutable_policy_change_requires_migration");
    generation = std::stoull(meta("policy", "1"));
    accepted_revision = std::stoll(meta("accepted_revision", "0"));
    view = std::make_unique<View>(conf);
    kernel = std::make_unique<Kernel>(conf);
    auto floor =
        std::max(kernel->watermark(),
                 __atomic_load_n(&view->data->reserved[1], __ATOMIC_SEQ_CST));
    if (conf.storage.persistent)
      require(floor <= audit_sequence(), "state_rollback_detected");
    else {
      require(floor < UINT64_MAX, "audit_sequence_exhausted");
      meta_set("audit_seq", std::to_string(floor));
      auto prior = __atomic_load_n(&view->data->generation, __ATOMIC_SEQ_CST);
      generation = std::max(generation, prior) + 1;
      meta_set("policy", std::to_string(generation));
    }
    if (meta("boot") != conf.boot) {
      auto oldboot = meta("boot");
      db.clear(Table::Requests);
      db.clear(Table::Evidence);
      for (auto &entry : db.rows(Table::Fences)) {
        auto f = parse(entry.second);
        set(f, "boot", std::string("0"));
        save(Table::Fences, entry.first, f);
      }
      int64_t saved_wall = std::stoll(meta("recovery_utc", "0")),
              saved_boot = std::stoll(meta("recovery_boot_ns", "0"));
      auto wall = utc(), monotonic = (int64_t)ban_now();
      for (auto &entry : db.rows(Table::Records)) {
        auto r = parse(entry.second);
        auto remaining = std::max<int64_t>(
            0, std::min(integer_text(r, "expires") - integer_text(r, "decided"),
                        integer_text(r, "expires") -
                            std::max(wall, saved_wall) - conf.skew_ms));
        if (saved_boot && str(r, "boot") == oldboot)
          remaining = std::min(
              remaining,
              std::max<int64_t>(
                  0, (integer_text(r, "deadline") - saved_boot) / 1000000 -
                         std::max<int64_t>(0, wall - saved_wall)));
        set(r, "deadline", scalar(monotonic + remaining * 1000000));
        set(r, "boot", conf.boot);
        save_record(entry.first, r);
      }
      meta_set("boot", conf.boot);
      meta_set("recovery_utc", scalar(wall));
      meta_set("recovery_boot_ns", scalar(monotonic));
    }
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  if (conf.storage.persistent)
    reconcile();
  else {
    // Keep already pinned deadlines while the Node obtains a fresh full set.
    __atomic_store_n(&view->data->reserved[0], 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&view->data->generation, generation, __ATOMIC_SEQ_CST);
    volatile_log_session(conf.event_log);
    volatile_log_session(conf.ip_log);
  }
  project();
  if (conf.role == "master")
    publish_snapshot();
}
Engine::~Engine() = default;
J Engine::record(const std::string &key) { return data(Table::Records, key); }
void Engine::save_record(const std::string &key, const J &r) {
  save(Table::Records, key, r);
}
void Engine::audit(const std::string &action, const J &r) {
  require(count("audit") < 200000, "audit_capacity");
  bool automatic = !db.in_transaction();
  if (automatic)
    db.begin();
  try {
    auto seq = audit_sequence();
    require(seq < INT64_MAX, "audit_sequence_exhausted");
    auto event = parse(dump(r));
    set(event, "action", action);
    set(event, "node_id", conf.node);
    set(event, "time_ms", scalar(utc()));
    db.put(Table::Audit, ban_store::number_key(seq + 1), dump(event));
    meta_set("audit_seq", std::to_string(seq + 1));
    if (automatic)
      db.commit();
  } catch (...) {
    if (automatic)
      db.rollback();
    throw;
  }
}
static J log_projection(const J &event, bool ip_only) {
  if (!ip_only)
    return parse(dump(event));
  json_object *ip = nullptr;
  if (!json_object_object_get_ex(event.get(), "ip", &ip))
    return {};
  auto out = object();
  for (const char *key :
       {"action", "node_id", "time_ms", "ip", "scope", "ban_id", "layer",
        "origin", "source", "reason", "decided", "expires", "generation",
        "applied", "apply_error"}) {
    json_object *value = nullptr;
    if (json_object_object_get_ex(event.get(), key, &value))
      json_object_object_add(out.get(), key, json_object_get(value));
  }
  return out;
}
static void append_log(Engine &engine, const std::string &path, bool ip_only) {
  int fd = safe_open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
  bool created = fd >= 0, changed = created;
  if (fd < 0 && errno == EEXIST)
    fd = safe_open(path, O_RDWR);
  require(fd >= 0, "log_open");
  struct stat st;
  require(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
              st.st_nlink == 1 && !(st.st_mode & 007),
          "log_permissions");
  try {
    int64_t last = 0;
    last = std::stoll(engine.meta("log_cursor:" + path, "0"));
    uint64_t scanned = std::stoull(engine.meta("log_scan:" + path, "0"));
    off_t size = st.st_size;
    std::string tail((size_t)std::min<off_t>(size, 131072), '\0');
    if (!tail.empty()) {
      require(pread(fd, tail.data(), tail.size(), size - (off_t)tail.size()) ==
                  (ssize_t)tail.size(),
              "log_read");
      auto end = tail.rfind('\n');
      if (end == std::string::npos) {
        require(size == (off_t)tail.size(), "log_corrupt");
        require(!ftruncate(fd, 0), "log_truncate");
        changed = true;
        tail.clear();
      } else {
        if (end + 1 != tail.size()) {
          require(!ftruncate(fd, size - (off_t)tail.size() + (off_t)end + 1),
                  "log_tail_recover");
          changed = true;
        }
        auto start = end ? tail.rfind('\n', end - 1) : std::string::npos;
        auto line =
            tail.substr(start == std::string::npos ? 0 : start + 1,
                        end - (start == std::string::npos ? 0 : start + 1));
        auto item = parse(line);
        auto file_last = integer_text(item, "seq");
        require(file_last >= last, "log_rollback");
        last = file_last;
        auto saved = engine.db.get(Table::Audit, ban_store::number_key(last));
        require(saved.has_value(), "log_ahead_of_state");
        auto expected = log_projection(parse(*saved), ip_only);
        require((bool)expected, "log_projection_mismatch");
        set(expected, "seq", scalar(last));
        require(dump(expected) == line, "log_record_mismatch");
      }
    }
    // The file may be durably ahead of its cursor when the other projection
    // or the cursor transaction failed. Its verified tail is already written.
    scanned = std::max(scanned, (uint64_t)last);
    require(lseek(fd, 0, SEEK_END) >= 0, "log_seek");
    bool written = false;
    while (true) {
      auto rows = engine.db.range(Table::Audit,
                                  ban_store::number_key(scanned + 1), "", 256);
      if (rows.empty())
        break;
      for (auto &row : rows) {
        scanned = std::stoull(row.first);
        auto event = log_projection(parse(row.second), ip_only);
        if (!event)
          continue;
        set(event, "seq", std::to_string(scanned));
        auto value = dump(event) + "\n";
        size_t done = 0;
        while (done < value.size()) {
          ssize_t n = write(fd, value.data() + done, value.size() - done);
          if (n < 0 && errno == EINTR)
            continue;
          require(n > 0, "log_write");
          done += (size_t)n;
        }
        last = (int64_t)scanned;
        written = true;
      }
    }
    if (written || changed)
      require(!fsync(fd), "log_sync");
    if (created) {
      int dir =
          safe_open(path.substr(0, path.rfind('/')), O_RDONLY | O_DIRECTORY);
      require(dir >= 0, "log_directory");
      bool ok = !fsync(dir);
      close(dir);
      require(ok, "log_directory_sync");
    }
    engine.meta_set("log_cursor:" + path, scalar(last));
    engine.meta_set("log_scan:" + path,
                    std::to_string(std::max(scanned, engine.audit_sequence())));
    if (lseek(fd, 0, SEEK_END) > 16 * 1024 * 1024) {
      auto slash = path.rfind('/');
      int directory = safe_open(path.substr(0, slash), O_RDONLY | O_DIRECTORY);
      require(directory >= 0, "log_rotate_directory");
      auto name = path.substr(slash + 1),
           archived = name + "." + scalar(last) + ".jsonl";
      bool ok =
          !renameat(directory, name.c_str(), directory, archived.c_str()) &&
          !fsync(directory);
      close(directory);
      require(ok, "log_rotate");
    }
    close(fd);
  } catch (...) {
    close(fd);
    throw;
  }
}
void Engine::project() {
  struct stat a, b;
  if (!stat(conf.event_log.c_str(), &a) && !stat(conf.ip_log.c_str(), &b))
    require(a.st_dev != b.st_dev || a.st_ino != b.st_ino, "aliased_logs");
  try {
    db.begin();
    append_log(*this, conf.event_log, false);
    append_log(*this, conf.ip_log, true);
    auto event_tail = std::stoull(meta("log_cursor:" + conf.event_log, "0"));
    auto ip_tail = std::stoull(meta("log_cursor:" + conf.ip_log, "0"));
    auto floor = std::min(std::stoull(meta("log_scan:" + conf.event_log, "0")),
                          std::stoull(meta("log_scan:" + conf.ip_log, "0")));
    for (auto &row :
         db.range(Table::Audit, "", ban_store::number_key(floor + 1))) {
      auto seq = std::stoull(row.first);
      if (seq != event_tail && seq != ip_tail)
        db.erase(Table::Audit, row.first);
    }
    db.commit();
    logs_ok = true;
  } catch (...) {
    db.rollback();
    logs_ok = false;
    throw;
  }
}
void Engine::insert_ban(const ban_event &e, int layer) {
  auto ip = ip_text(e.ip), scope = layer == 7 ? std::string(e.scope) : "";
  auto key = address_key(ip, scope);
  auto existing = record(key);
  if (existing && integer_text(existing, "deadline") > (int64_t)ban_now())
    return;
  require(count("records") < BAN_CAPACITY, "active_capacity");
  auto r = object();
  set(r, "ip", ip);
  set(r, "scope", scope);
  set(r, "ban_id", random_id());
  set(r, "reason", std::string(e.reason));
  set(r, "source", conf.node);
  set(r, "origin", std::string("local"));
  set(r, "layer", layer);
  set(r, "waf", layer == 7 ? 1 : 0);
  set(r, "generation", scalar(generation));
  set(r, "boot", conf.boot);
  auto duration = layer == 7 ? conf.l7 : conf.l3;
  set(r, "decided", scalar(utc()));
  set(r, "expires", scalar(utc() + duration * 1000));
  set(r, "deadline", scalar((int64_t)ban_now() + duration * 1000000000));
  set(r, "proposal_seq", std::string("0"));
  set(r, "accepted", std::string("0"));
  set(r, "applied", 0);
  if (layer == 3) {
    require(count("outbox") < 16384, "outbox_capacity");
    int64_t seq = std::stoll(meta("local_seq", "0")) + 1;
    set(r, "proposal_seq", scalar(seq));
    auto proposal = parse(dump(r));
    set(proposal, "seq", scalar(seq));
    set(proposal, "event_id", str(r, "ban_id"));
    auto out = object();
    set(out, "value", proposal);
    set(out, "accepted", std::string("0"));
    save(Table::Outbox, ban_store::number_key(seq), out);
    meta_set("local_seq", scalar(seq));
  }
  audit("PREPARE", r);
  save_record(key, r);
  meta_set("recovery_utc", scalar(utc()));
  meta_set("recovery_boot_ns", scalar((int64_t)ban_now()));
}
void Engine::delete_ban(const std::string &key, const std::string &action) {
  auto r = record(key);
  if (!r)
    return;
  db.erase(Table::Records, key);
  audit(action, r);
  if (action == "SUPERSEDED")
    return;
  auto ip = str(r, "ip");
  for (auto &entry : db.range(Table::Evidence, ip + "|", ip + "}"))
    db.erase(Table::Evidence, entry.first);
  auto fence = data(Table::Fences, ip);
  auto now_utc = utc(), now_boot = (int64_t)ban_now();
  if (fence) {
    now_utc = std::max(now_utc, integer_text(fence, "utc"));
    now_boot = std::max(now_boot, integer_text(fence, "boot"));
  }
  auto f = object();
  set(f, "utc", scalar(now_utc));
  set(f, "boot", scalar(now_boot));
  save(Table::Fences, ip, f);
}
ban_ack Engine::event(const ban_event &e, uint32_t uid) {
  ban_ack ack{BAN_VERSION, 0, e.sequence, 0};
  require(e.version == BAN_VERSION && e.type == BAN_EVENT && e.sequence > 0,
          "event_header");
  require(uid == conf.worker_uid && conf.instances.count(hex(e.instance, 16)),
          "producer_identity");
  uint8_t boot[16];
  require(ban_uuid(conf.boot.c_str(), boot) && !memcmp(boot, e.boot, 16),
          "event_boot");
  require(memchr(e.scope, 0, 96) && memchr(e.reason, 0, 64) &&
              id_valid(e.scope),
          "event_scope");
  require(e.ip.family == 4 || e.ip.family == 6, "event_family");
  if (e.ip.family == 4) {
    uint8_t zero[12] = {0};
    require(!memcmp(e.ip.address, zero, 12), "ipv4_encoding");
  }
  auto producer = hex(e.producer, 16),
       digest = sha(std::string((const char *)&e, sizeof(e))),
       ip = ip_text(e.ip);
  auto prior = producer_sequence(producer);
  if (e.sequence <= prior) {
    auto receipt = data(Table::Receipts,
                        producer + "|" + ban_store::number_key(e.sequence));
    require(receipt && str(receipt, "digest") == digest,
            "event_replay_conflict");
    ack.durable = (uint64_t)integer_text(receipt, "durable");
    return ack;
  }
  require(e.sequence == (uint64_t)prior + 1, "producer_sequence_gap");
  if (!prior)
    require(count("producers") < 16384, "producer_capacity");
  auto now = ban_now();
  bool timely = e.observed_ns <= now + 1000000 &&
                e.observed_ns + conf.event_age * 1000000u >= now &&
                e.generation == generation;
  require(e.source >= BAN_WAF && e.source <= BAN_HIT, "event_source");
  if (e.source != BAN_HIT)
    require(
        reason_valid(e.reason) &&
            conf.rules.count(std::string(e.source == BAN_WAF ? "waf:" : "cc:") +
                             e.reason),
        "unregistered_rule");
  auto request = hex(e.instance, 16) + hex(e.request, 16);
  bool duplicate = false;
  bool enforcement_changed = false;
  int previous_source = 0;
  if (auto previous = data(Table::Requests, request)) {
    duplicate = true;
    previous_source = (int)num(previous, "source");
  }
  auto active = record(address_key(ip, ""));
  if (!active)
    active = record("cluster|" + ip);
  if (active && integer_text(active, "deadline") <= (int64_t)now)
    active.reset();
  auto l7 = record(address_key(ip, e.scope));
  bool hit =
      e.source != BAN_HIT || (l7 && num(l7, "waf") == 1 &&
                              integer_text(l7, "deadline") > (int64_t)now &&
                              str(l7, "ban_id") == hex(e.observed, 16));
  if (auto fence = data(Table::Fences, ip))
    if (e.observed_ns <= (uint64_t)integer_text(fence, "boot"))
      timely = false;
  db.begin();
  try {
    if (timely && hit && !exempt(conf, e.ip) && !active) {
      require(duplicate || count("requests") < 65536, "request_capacity");
      if (!duplicate) {
        auto r = object();
        set(r, "ip", ip);
        set(r, "observed", std::to_string(e.observed_ns));
        set(r, "source", e.source);
        save(Table::Requests, request, r);
      }
      if (e.source == BAN_CC) {
        if (!duplicate || previous_source != BAN_CC) {
          insert_ban(e, 3);
          enforcement_changed = true;
        }
      } else if (!duplicate) {
        if (e.source == BAN_WAF) {
          insert_ban(e, 7);
          enforcement_changed = true;
        }
        db.put(Table::Evidence, ip + "|" + request,
               std::to_string(e.observed_ns));
        size_t hits = 0;
        for (auto &entry : db.range(Table::Evidence, ip + "|", ip + "}"))
          if (std::stoll(entry.second) > (int64_t)now - conf.window * 1000000)
            hits++;
        if (hits >= (size_t)conf.threshold) {
          insert_ban(e, 3);
          enforcement_changed = true;
        }
      }
    }
    db.put(Table::Producers, producer, std::to_string(e.sequence));
    auto receipt_seq = std::stoull(meta("receipt_seq", "0"));
    require(receipt_seq < INT64_MAX, "receipt_sequence_exhausted");
    ack.durable = receipt_seq + 1;
    meta_set("receipt_seq", std::to_string(ack.durable));
    auto receipt = object();
    set(receipt, "digest", digest);
    set(receipt, "durable", std::to_string(ack.durable));
    save(Table::Receipts, producer + "|" + ban_store::number_key(e.sequence),
         receipt);
    if (e.sequence > 2049)
      db.erase(Table::Receipts,
               producer + "|" + ban_store::number_key(e.sequence - 2049));
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  if (db.in_transaction()) {
    if (enforcement_changed)
      enforcement_pending = true;
    return ack;
  }
  if (!conf.storage.persistent && accepted_revision == 0) {
    ack.result = 4;
    return ack;
  }
  // Receipt/evidence-only traffic has no datapath or log projection to change.
  // The periodic tick still retries earlier failed enforcement and projection.
  if (!enforcement_changed && logs_ok && !enforcement_pending)
    return ack;
  try {
    reconcile();
    project();
  } catch (...) {
    ack.result = 4;
  }
  return ack;
}
std::vector<std::optional<ban_ack>>
Engine::events(const std::vector<std::pair<ban_event, uint32_t>> &batch) {
  require(batch.size() <= 128, "event_batch_limit");
  std::vector<std::optional<ban_ack>> acknowledgements;
  acknowledgements.reserve(batch.size());
  db.begin();
  try {
    for (auto &input : batch) {
      try {
        acknowledgements.push_back(event(input.first, input.second));
      } catch (const std::exception &) {
        acknowledgements.push_back(std::nullopt);
      }
    }
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  if (!conf.storage.persistent && accepted_revision == 0) {
    for (auto &ack : acknowledgements)
      if (ack)
        ack->result = 4;
    return acknowledgements;
  }
  if (enforcement_pending || !logs_ok) {
    try {
      reconcile();
      project();
    } catch (...) {
      for (auto &ack : acknowledgements)
        if (ack)
          ack->result = 4;
    }
  }
  return acknowledgements;
}
static ban_record view_record(const J &r) {
  ban_record out{};
  out.ip = ip_parse(str(r, "ip"));
  auto scope = str(r, "scope");
  memcpy(out.scope, scope.data(), scope.size());
  auto id = str(r, "ban_id");
  require(id.size() == 32, "ban_id_size");
  for (size_t i = 0; i < 16; i++)
    out.id[i] = (uint8_t)std::stoi(id.substr(2 * i, 2), nullptr, 16);
  out.deadline = (uint64_t)integer_text(r, "deadline");
  out.generation = (uint64_t)integer_text(r, "generation");
  out.layer = (uint32_t)num(r, "layer");
  out.local_waf = (uint32_t)num(r, "waf");
  return out;
}
void Engine::reconcile() {
  enforcement_pending = true;
  std::map<std::string, J> desired;
  std::vector<std::pair<std::string, J>> rows;
  auto now = ban_now();
  for (auto &row : db.rows(Table::Records))
    rows.push_back({row.first, parse(row.second)});
  for (auto &r : rows) {
    if (integer_text(r.second, "deadline") <= (int64_t)now)
      continue;
    auto key = address_key(str(r.second, "ip"), str(r.second, "scope"));
    auto old = desired.find(key);
    if (old == desired.end() || integer_text(old->second, "deadline") >
                                    integer_text(r.second, "deadline"))
      desired[key] = r.second;
  }
  auto installed = kernel->entries();
  std::set<std::string> l3;
  std::set<std::string> failed;
  for (auto &r : desired) {
    if (num(r.second, "layer") != 3)
      continue;
    auto rec = view_record(r.second);
    ban_kernel_value value{rec.deadline, {}, rec.generation};
    memcpy(value.id, rec.id, 16);
    auto ip = str(r.second, "ip");
    auto old = installed.find(ip);
    try {
      if (old == installed.end() || memcmp(&old->second, &value, sizeof(value)))
        kernel->put(rec.ip, value);
    } catch (...) {
      failed.insert(ip);
      rec.layer = 7;
      rec.local_waf = 0;
      int64_t remaining = std::max<int64_t>(
          0, integer_text(r.second, "decided") + conf.l7 * 1000 - utc());
      rec.deadline = std::min<uint64_t>(
          rec.deadline, ban_now() + (uint64_t)remaining * 1000000);
      if (remaining)
        view->publish(rec);
      continue;
    }
    view->publish(rec);
    l3.insert(ip);
  }
  for (auto &r : desired) {
    if (num(r.second, "layer") != 7)
      continue;
    if (l3.count(str(r.second, "ip")))
      continue;
    view->publish(view_record(r.second));
  }
  for (auto &r : installed)
    if (!l3.count(r.first) && !failed.count(r.first))
      kernel->remove(ip_parse(r.first));
  // Reconcile the same inode after Agent restart, never clear the whole view.
  for (size_t i = 0; i < BAN_SLOTS; i++) {
    auto &s = view->data->table[i];
    uint64_t word = __atomic_load_n(&s.commit, __ATOMIC_SEQ_CST),
             raw[BAN_WORDS];
    for (size_t k = 0; k < BAN_WORDS; k++)
      raw[k] = __atomic_load_n(&s.bank[word & 1][k], __ATOMIC_SEQ_CST);
    ban_record r{};
    memcpy(&r, raw, sizeof(r));
    if (r.layer < 3)
      continue;
    auto key = address_key(ip_text(r.ip), r.scope);
    if (!desired.count(key) || (r.layer == 7 && l3.count(ip_text(r.ip))))
      view->publish(r, true);
  }
  db.begin();
  try {
    for (auto &r : rows) {
      if (num(r.second, "layer") == 3 && failed.count(str(r.second, "ip"))) {
        json_object *value = nullptr;
        if (!json_object_object_get_ex(r.second.get(), "apply_error", &value)) {
          set(r.second, "apply_error", std::string("kernel_apply_failed"));
          save_record(r.first, r.second);
          audit("APPLY_FAILED", r.second);
        }
        continue;
      }
      if (num(r.second, "layer") == 7 && l3.count(str(r.second, "ip"))) {
        delete_ban(r.first, "SUPERSEDED");
        continue;
      }
      if (!num(r.second, "applied") &&
          integer_text(r.second, "deadline") > (int64_t)now) {
        set(r.second, "applied", 1);
        save_record(r.first, r.second);
        audit("APPLIED", r.second);
      }
    }
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  __atomic_store_n(&view->data->generation, generation, __ATOMIC_SEQ_CST);
  {
    auto seq = audit_sequence();
    kernel->watermark(seq);
    __atomic_store_n(&view->data->reserved[1], seq, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&view->data->heartbeat, ban_now(), __ATOMIC_SEQ_CST);
  __atomic_store_n(&view->data->reserved[0], accepted_revision > 0 ? 1 : 0,
                   __ATOMIC_SEQ_CST);
  require(failed.empty(), "kernel_apply_failed_fallback_only");
  enforcement_pending = false;
}
void Engine::tick() {
  if (!conf.storage.persistent && accepted_revision == 0) {
    // An unavailable authority is not an empty desired set. Kernel deadlines
    // remain bounded by their original expiry while the Node waits for sync.
    project();
    return;
  }
  int64_t now = (int64_t)ban_now();
  std::vector<std::string> expired;
  for (auto &row : db.rows(Table::Records))
    if (integer_text(parse(row.second), "deadline") <= now)
      expired.push_back(row.first);
  if (!expired.empty()) {
    db.begin();
    try {
      for (auto &key : expired)
        delete_ban(key, "EXPIRED");
      db.commit();
    } catch (...) {
      db.rollback();
      throw;
    }
  }
  db.begin();
  try {
    for (auto &row : db.rows(Table::Evidence))
      if (std::stoll(row.second) < now - conf.window * 1000000)
        db.erase(Table::Evidence, row.first);
    for (auto &row : db.rows(Table::Requests))
      if (integer_text(parse(row.second), "observed") <
          now - (conf.window + conf.event_age) * 1000000)
        db.erase(Table::Requests, row.first);
    meta_set("recovery_utc", scalar(utc()));
    meta_set("recovery_boot_ns", scalar((int64_t)ban_now()));
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  try {
    reconcile();
  } catch (...) {
    project();
    throw;
  }
  project();
}
J Engine::status() {
  auto out = object();
  set(out, "node_id", conf.node);
  set(out, "kernel_ready", kernel->ready ? 1 : 0);
  set(out, "active", count("records"));
  int64_t pending = 0;
  for (auto &row : db.rows(Table::Records))
    if (!num(parse(row.second), "applied"))
      pending++;
  set(out, "pending_enforcement", pending);
  auto storage = object();
  const auto &stats = db.stats();
  set(storage, "mode", std::string(stats.persistent ? "persistent" : "memory"));
  set(storage, "durable", stats.persistent ? 1 : 0);
  set(storage, "entries", (int64_t)stats.entries);
  set(storage, "accounted_bytes", (int64_t)stats.bytes);
  set(storage, "log_bytes", (int64_t)stats.log_bytes);
  set(storage, "transactions", (int64_t)stats.transactions);
  set(storage, "syncs", (int64_t)stats.syncs);
  set(storage, "checkpoints", (int64_t)stats.checkpoints);
  set(storage, "checkpoint_error", stats.checkpoint_error);
  set(out, "storage", storage);
  set(out, "logs_durable", logs_ok ? 1 : 0);
  set(out, "policy_generation", scalar(generation));
  set(out, "cluster_revision", scalar(accepted_revision));
  set(out, "sync_error", sync_error);
  set(out, "policy_error", policy_error);
  set(out, "pending_proposals", count("outbox"));
  set(out, "role", conf.role);
  if (conf.role == "master") {
    int64_t revision = std::stoll(meta("revision", "1")), pending = 0;
    auto digest = meta("snapshot_digest");
    for (auto &node : conf.members) {
      auto result = data(Table::Results, node);
      if (!result || integer_text(result, "revision") != revision ||
          str(result, "digest") != digest ||
          str(result, "state") != "applied" ||
          std::stoll(meta("result_seen:" + node, "0")) <
              utc() - std::max<int64_t>(10000, conf.poll_ms * 3))
        pending++;
    }
    set(out, "desired_revision", scalar(revision));
    set(out, "pending_nodes", pending);
    set(out, "cluster_state", std::string(pending ? "PARTIAL" : "ALL_APPLIED"));
  }
  return out;
}
J Engine::query(const J &j) {
  auto operation = str(j, "operation");
  if (operation == "snapshot") {
    keys(j, "operation");
    require(conf.role == "master", "authority_required");
    return snapshot();
  }
  if (operation == "checkpoint") {
    keys(j, "operation");
    db.checkpoint();
    return status();
  }
  if (operation == "status") {
    keys(j, "operation");
    return status();
  }
  if (operation == "list") {
    keys(j, "operation");
    auto out = object(), list = own(json_object_new_array());
    for (auto &row : db.rows(Table::Records))
      json_object_array_add(list.get(),
                            json_object_get(parse(row.second).get()));
    set(out, "records", list);
    return out;
  }
  if (operation == "unban") {
    keys(j, "operation ip ban_id");
    auto ip = ip_text(ip_parse(str(j, "ip"))), id = str(j, "ban_id");
    db.begin();
    try {
      std::vector<std::string> remove;
      for (auto &row : db.rows(Table::Records)) {
        auto r = parse(row.second);
        if (str(r, "ip") == ip && str(r, "ban_id") == id) {
          require(conf.role == "master" || num(r, "layer") == 7,
                  "global_unban_requires_authority");
          remove.push_back(row.first);
        }
      }
      require(!remove.empty(), "ban_id_mismatch");
      for (auto &key : remove)
        delete_ban(key, "UNBAN");
      if (conf.role == "master") {
        db.erase(Table::Globals, ip);
        meta_set("revision", scalar(std::stoll(meta("revision")) + 1));
      }
      db.commit();
    } catch (...) {
      db.rollback();
      throw;
    }
    reconcile();
    project();
    if (conf.role == "master")
      publish_snapshot();
    return status();
  }
  throw std::runtime_error("unknown_admin_operation");
}
void Engine::reload(const Config &next) {
  require(next.immutable == conf.immutable, "reload_requires_maintenance");
  require(next.storage.max_entries == conf.storage.max_entries &&
              next.storage.max_bytes == conf.storage.max_bytes &&
              next.storage.checkpoint_bytes == conf.storage.checkpoint_bytes,
          "storage_options_require_restart");
  require(generation < INT64_MAX, "policy_sequence_exhausted");
  auto candidate = generation + 1;
  db.begin();
  try {
    meta_set("policy", std::to_string(candidate));
    db.clear(Table::Evidence);
    db.clear(Table::Requests);
    auto r = object();
    set(r, "generation", std::to_string(candidate));
    audit("POLICY_UPDATED", r);
    db.commit();
  } catch (...) {
    db.rollback();
    throw;
  }
  generation = candidate;
  conf.l7 = next.l7;
  conf.l3 = next.l3;
  conf.window = next.window;
  conf.threshold = next.threshold;
  conf.event_age = next.event_age;
  policy_error.clear();
  reconcile();
  project();
}
} // namespace ban
