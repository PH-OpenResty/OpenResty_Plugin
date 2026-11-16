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
void Engine::sql(const char *s) {
  require(sqlite3_exec(db, s, nullptr, nullptr, nullptr) == SQLITE_OK,
          "database_transaction");
}
std::string Engine::meta(const std::string &key, const std::string &fallback) {
  Statement q(db, "SELECT value FROM meta WHERE key=?");
  q.bind(1, key);
  return q.row() ? q.text(0) : fallback;
}
void Engine::meta_set(const std::string &key, const std::string &value) {
  Statement q(db, "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET "
                  "value=excluded.value");
  q.bind(1, key);
  q.bind(2, value);
  q.done();
}
int64_t Engine::count(const char *table) {
  std::string s = "SELECT COUNT(*) FROM " + std::string(table);
  Statement q(db, s.c_str());
  require(q.row(), "database_count");
  return q.integer(0);
}
Engine::Engine(Config c) : conf(std::move(c)) {
  auto dbpath = conf.state + "/state.sqlite";
  int fd = safe_open(dbpath, O_RDWR | O_CREAT, 0600);
  require(fd >= 0, "state_file");
  struct stat st;
  require(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
              !(st.st_mode & 077) && st.st_uid == geteuid(),
          "state_file_permissions");
  close(fd);
  require(sqlite3_open_v2(dbpath.c_str(), &db,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                          nullptr) == SQLITE_OK,
          "database_open");
  sqlite3_busy_timeout(db, 1000);
  sql("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA "
      "foreign_keys=ON; PRAGMA wal_autocheckpoint=100;");
  {
    Statement q(db, "PRAGMA integrity_check");
    require(q.row() && q.text(0) == "ok", "database_corrupt");
  }
  sql("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT "
      "NULL);"
      "CREATE TABLE IF NOT EXISTS records(key TEXT PRIMARY KEY,value TEXT NOT "
      "NULL);"
      "CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY "
      "AUTOINCREMENT,ts INTEGER NOT NULL,value TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS producers(id TEXT PRIMARY KEY,seq INTEGER "
      "NOT NULL);"
      "CREATE TABLE IF NOT EXISTS receipts(producer TEXT,seq INTEGER,digest "
      "TEXT NOT NULL,durable INTEGER NOT NULL,PRIMARY KEY(producer,seq));"
      "CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,ip "
      "TEXT,observed INTEGER,source INTEGER);"
      "CREATE TABLE IF NOT EXISTS evidence(ip TEXT,request TEXT PRIMARY "
      "KEY,observed INTEGER);"
      "CREATE INDEX IF NOT EXISTS evidence_ip ON evidence(ip,observed);"
      "CREATE TABLE IF NOT EXISTS fences(ip TEXT PRIMARY KEY,utc INTEGER NOT "
      "NULL,boot INTEGER NOT NULL);"
      "CREATE TABLE IF NOT EXISTS outbox(seq INTEGER PRIMARY KEY,value TEXT "
      "NOT NULL,accepted INTEGER NOT NULL DEFAULT 0);"
      "CREATE TABLE IF NOT EXISTS globals(ip TEXT PRIMARY KEY,value TEXT NOT "
      "NULL);"
      "CREATE TABLE IF NOT EXISTS origin_receipts(node TEXT,seq INTEGER,digest "
      "TEXT,revision INTEGER,PRIMARY KEY(node,seq));"
      "CREATE TABLE IF NOT EXISTS origin_high(node TEXT PRIMARY KEY,seq "
      "INTEGER NOT NULL);"
      "CREATE TABLE IF NOT EXISTS results(node TEXT PRIMARY KEY,revision "
      "INTEGER,digest TEXT,state TEXT);");
  require(meta("version", "1") == "1", "database_version");
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
  {
    Statement q(db, "SELECT COALESCE(MAX(seq),0) FROM audit");
    require(q.row(), "audit_watermark");
    auto seq = (uint64_t)q.integer(0);
    require(kernel->watermark() <= seq &&
                __atomic_load_n(&view->data->reserved[1], __ATOMIC_SEQ_CST) <=
                    seq,
            "state_rollback_detected");
  }
  auto oldboot = meta("boot");
  if (oldboot != conf.boot) {
    sql("BEGIN IMMEDIATE");
    sql("DELETE FROM requests; DELETE FROM evidence;");
    Statement q(db, "SELECT key,value FROM records");
    std::vector<std::pair<std::string, J>> all;
    while (q.row())
      all.push_back({q.text(0), parse(q.text(1))});
    for (auto &r : all) {
      auto remaining = std::max<int64_t>(0, integer_text(r.second, "expires") -
                                                utc() - conf.skew_ms);
      set(r.second, "deadline",
          scalar((int64_t)ban_now() + remaining * 1000000));
      set(r.second, "boot", conf.boot);
      save_record(r.first, r.second);
    }
    meta_set("boot", conf.boot);
    sql("COMMIT");
  }
  reconcile();
  project();
  if (conf.role == "master")
    publish_snapshot();
}
Engine::~Engine() {
  if (db)
    sqlite3_close(db);
}
J Engine::record(const std::string &key) {
  Statement q(db, "SELECT value FROM records WHERE key=?");
  q.bind(1, key);
  return q.row() ? parse(q.text(0)) : J{};
}
void Engine::save_record(const std::string &key, const J &r) {
  Statement q(db, "INSERT INTO records VALUES(?,?) ON CONFLICT(key) DO UPDATE "
                  "SET value=excluded.value");
  q.bind(1, key);
  q.bind(2, dump(r));
  q.done();
}
void Engine::audit(const std::string &action, const J &r) {
  require(count("audit") < 200000, "audit_capacity");
  auto event = parse(dump(r));
  set(event, "action", action);
  set(event, "node_id", conf.node);
  set(event, "time_ms", scalar(utc()));
  Statement q(db, "INSERT INTO audit(ts,value) VALUES(?,?)");
  q.bind(1, utc());
  q.bind(2, dump(event));
  q.done();
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
static void append_log(sqlite3 *db, const std::string &path, bool ip_only) {
  int fd = safe_open(path, O_RDWR | O_CREAT, 0600);
  require(fd >= 0, "log_open");
  struct stat st;
  require(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
              st.st_nlink == 1 && !(st.st_mode & 007),
          "log_permissions");
  try {
    int64_t last = 0;
    {
      Statement cursor(db, "SELECT value FROM meta WHERE key=?");
      cursor.bind(1, "log_cursor:" + path);
      if (cursor.row())
        last = std::stoll(cursor.text(0));
    }
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
        tail.clear();
      } else {
        if (end + 1 != tail.size())
          require(!ftruncate(fd, size - (off_t)tail.size() + (off_t)end + 1),
                  "log_tail_recover");
        auto start = end ? tail.rfind('\n', end - 1) : std::string::npos;
        auto line =
            tail.substr(start == std::string::npos ? 0 : start + 1,
                        end - (start == std::string::npos ? 0 : start + 1));
        auto item = parse(line);
        auto file_last = integer_text(item, "seq");
        require(file_last >= last, "log_rollback");
        last = file_last;
        Statement q(db, "SELECT value FROM audit WHERE seq=?");
        q.bind(1, last);
        require(q.row(), "log_ahead_of_state");
        auto expected = log_projection(parse(q.text(0)), ip_only);
        require((bool)expected, "log_projection_mismatch");
        set(expected, "seq", scalar(last));
        require(dump(expected) == line, "log_record_mismatch");
      }
    }
    Statement q(db,
                "SELECT seq,value FROM audit WHERE seq>? AND (?=0 OR "
                "json_type(value,'$.ip') IS NOT NULL) ORDER BY seq LIMIT 256");
    q.bind(1, last);
    q.bind(2, ip_only ? 1 : 0);
    require(lseek(fd, 0, SEEK_END) >= 0, "log_seek");
    while (q.row()) {
      auto event = log_projection(parse(q.text(1)), ip_only);
      if (!event)
        continue;
      set(event, "seq", scalar(q.integer(0)));
      last = q.integer(0);
      auto text = dump(event) + "\n";
      size_t done = 0;
      while (done < text.size()) {
        ssize_t n = write(fd, text.data() + done, text.size() - done);
        if (n < 0 && errno == EINTR)
          continue;
        require(n > 0, "log_write");
        done += (size_t)n;
      }
    }
    require(!fsync(fd), "log_sync");
    {
      Statement cursor(db, "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO "
                           "UPDATE SET value=excluded.value");
      cursor.bind(1, "log_cursor:" + path);
      cursor.bind(2, scalar(last));
      cursor.done();
    }
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
    Statement pending(db, "SELECT COUNT(*) FROM audit WHERE seq>? AND (?=0 OR "
                          "json_type(value,'$.ip') IS NOT NULL)");
    pending.bind(1, last);
    pending.bind(2, ip_only ? 1 : 0);
    require(pending.row() && !pending.integer(0), "log_backlog");
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
    append_log(db, conf.event_log, false);
    append_log(db, conf.ip_log, true);
    logs_ok = true;
  } catch (...) {
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
    Statement q(db, "INSERT INTO outbox VALUES(?,?,0)");
    q.bind(1, seq);
    q.bind(2, dump(proposal));
    q.done();
    meta_set("local_seq", scalar(seq));
  }
  audit("PREPARE", r);
  save_record(key, r);
}
void Engine::delete_ban(const std::string &key, const std::string &action) {
  auto r = record(key);
  if (!r)
    return;
  Statement q(db, "DELETE FROM records WHERE key=?");
  q.bind(1, key);
  q.done();
  audit(action, r);
  if (action == "SUPERSEDED")
    return;
  Statement e(db, "DELETE FROM evidence WHERE ip=?");
  e.bind(1, str(r, "ip"));
  e.done();
  Statement f(db, "INSERT INTO fences VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE "
                  "SET utc=MAX(utc,excluded.utc),boot=MAX(boot,excluded.boot)");
  f.bind(1, str(r, "ip"));
  f.bind(2, utc());
  f.bind(3, (int64_t)ban_now());
  f.done();
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
  int64_t prior = 0;
  {
    Statement q(db, "SELECT seq FROM producers WHERE id=?");
    q.bind(1, producer);
    if (q.row())
      prior = q.integer(0);
  }
  if (e.sequence <= (uint64_t)prior) {
    Statement q(
        db, "SELECT digest,durable FROM receipts WHERE producer=? AND seq=?");
    q.bind(1, producer);
    q.bind(2, (int64_t)e.sequence);
    require(q.row() && q.text(0) == digest, "event_replay_conflict");
    ack.durable = q.integer(1);
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
  int previous_source = 0;
  {
    Statement q(db, "SELECT source FROM requests WHERE id=?");
    q.bind(1, request);
    if (q.row()) {
      duplicate = true;
      previous_source = q.integer(0);
    }
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
  {
    Statement q(db, "SELECT boot FROM fences WHERE ip=?");
    q.bind(1, ip);
    if (q.row() && e.observed_ns <= (uint64_t)q.integer(0))
      timely = false;
  }
  sql("BEGIN IMMEDIATE");
  try {
    if (timely && hit && !exempt(conf, e.ip) && !active) {
      require(duplicate || count("requests") < 65536, "request_capacity");
      if (!duplicate) {
        Statement q(db, "INSERT INTO requests VALUES(?,?,?,?)");
        q.bind(1, request);
        q.bind(2, ip);
        q.bind(3, (int64_t)e.observed_ns);
        q.bind(4, (int64_t)e.source);
        q.done();
      }
      if (e.source == BAN_CC) {
        if (!duplicate || previous_source != BAN_CC)
          insert_ban(e, 3);
      } else if (!duplicate) {
        if (e.source == BAN_WAF)
          insert_ban(e, 7);
        Statement q(db, "INSERT INTO evidence VALUES(?,?,?)");
        q.bind(1, ip);
        q.bind(2, request);
        q.bind(3, (int64_t)e.observed_ns);
        q.done();
        Statement countq(
            db, "SELECT COUNT(*) FROM evidence WHERE ip=? AND observed>?");
        countq.bind(1, ip);
        countq.bind(2, (int64_t)now - conf.window * 1000000);
        require(countq.row(), "evidence_count");
        if (countq.integer(0) >= conf.threshold)
          insert_ban(e, 3);
      }
    }
    Statement p(db, "INSERT INTO producers VALUES(?,?) ON CONFLICT(id) DO "
                    "UPDATE SET seq=excluded.seq");
    p.bind(1, producer);
    p.bind(2, (int64_t)e.sequence);
    p.done();
    ack.durable = (uint64_t)std::max<int64_t>(1, sqlite3_last_insert_rowid(db));
    Statement receipt(db, "INSERT INTO receipts VALUES(?,?,?,?)");
    receipt.bind(1, producer);
    receipt.bind(2, (int64_t)e.sequence);
    receipt.bind(3, digest);
    receipt.bind(4, (int64_t)ack.durable);
    receipt.done();
    Statement gc(db, "DELETE FROM receipts WHERE producer=? AND seq<?");
    gc.bind(1, producer);
    gc.bind(2, (int64_t)e.sequence - 2048);
    gc.done();
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
  try {
    reconcile();
    project();
  } catch (...) {
    ack.result = 4;
  }
  return ack;
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
  std::map<std::string, J> desired;
  Statement q(db, "SELECT key,value FROM records");
  std::vector<std::pair<std::string, J>> rows;
  auto now = ban_now();
  while (q.row())
    rows.push_back({q.text(0), parse(q.text(1))});
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
  sql("BEGIN IMMEDIATE");
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
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
  __atomic_store_n(&view->data->generation, generation, __ATOMIC_SEQ_CST);
  {
    Statement q(db, "SELECT COALESCE(MAX(seq),0) FROM audit");
    require(q.row(), "audit_watermark");
    auto seq = (uint64_t)q.integer(0);
    kernel->watermark(seq);
    __atomic_store_n(&view->data->reserved[1], seq, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&view->data->heartbeat, ban_now(), __ATOMIC_SEQ_CST);
  __atomic_store_n(&view->data->reserved[0], accepted_revision > 0 ? 1 : 0,
                   __ATOMIC_SEQ_CST);
  require(failed.empty(), "kernel_apply_failed_fallback_only");
}
void Engine::tick() {
  int64_t now = (int64_t)ban_now();
  Statement q(db, "SELECT key,value FROM records");
  std::vector<std::string> expired;
  while (q.row())
    if (integer_text(parse(q.text(1)), "deadline") <= now)
      expired.push_back(q.text(0));
  if (!expired.empty()) {
    sql("BEGIN IMMEDIATE");
    try {
      for (auto &key : expired)
        delete_ban(key, "EXPIRED");
      sql("COMMIT");
    } catch (...) {
      sql("ROLLBACK");
      throw;
    }
  }
  {
    Statement q(db, "DELETE FROM evidence WHERE observed<?");
    q.bind(1, now - conf.window * 1000000);
    q.done();
    Statement d(db, "DELETE FROM requests WHERE observed<?");
    d.bind(1, now - (conf.window + conf.event_age) * 1000000);
    d.done();
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
  {
    Statement q(
        db,
        "SELECT COUNT(*) FROM records WHERE json_extract(value,'$.applied')=0");
    require(q.row(), "pending_count");
    set(out, "pending_enforcement", q.integer(0));
  }
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
      Statement q(db, "SELECT revision,digest,state FROM results WHERE node=?");
      q.bind(1, node);
      if (!q.row() || q.integer(0) != revision || q.text(1) != digest ||
          q.text(2) != "applied")
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
  if (operation == "status") {
    keys(j, "operation");
    return status();
  }
  if (operation == "list") {
    keys(j, "operation");
    auto out = object(), list = own(json_object_new_array());
    Statement q(db, "SELECT value FROM records ORDER BY key");
    while (q.row())
      json_object_array_add(list.get(),
                            json_object_get(parse(q.text(0)).get()));
    set(out, "records", list);
    return out;
  }
  if (operation == "unban") {
    keys(j, "operation ip ban_id");
    auto ip = ip_text(ip_parse(str(j, "ip"))), id = str(j, "ban_id");
    sql("BEGIN IMMEDIATE");
    try {
      Statement q(
          db,
          "SELECT key,value FROM records WHERE json_extract(value,'$.ip')=?");
      q.bind(1, ip);
      std::vector<std::string> remove;
      while (q.row())
        if (str(parse(q.text(1)), "ban_id") == id) {
          require(conf.role == "master" || num(parse(q.text(1)), "layer") == 7,
                  "global_unban_requires_authority");
          remove.push_back(q.text(0));
        }
      require(!remove.empty(), "ban_id_mismatch");
      for (auto &key : remove)
        delete_ban(key, "UNBAN");
      if (conf.role == "master") {
        Statement d(db, "DELETE FROM globals WHERE ip=?");
        d.bind(1, ip);
        d.done();
        meta_set("revision", scalar(std::stoll(meta("revision")) + 1));
      }
      sql("COMMIT");
    } catch (...) {
      sql("ROLLBACK");
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
  generation++;
  meta_set("policy", scalar(generation));
  conf.l7 = next.l7;
  conf.l3 = next.l3;
  conf.window = next.window;
  conf.threshold = next.threshold;
  conf.event_age = next.event_age;
  policy_error.clear();
  sql("DELETE FROM evidence; DELETE FROM requests;");
  auto r = object();
  set(r, "generation", scalar(generation));
  audit("POLICY_UPDATED", r);
  reconcile();
  project();
}
} // namespace ban
