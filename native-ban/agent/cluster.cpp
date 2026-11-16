#include "ban.hpp"
#include <algorithm>
#include <cstring>
#include <sys/timex.h>
namespace ban {
static int64_t integer(const J &j, const char *k) {
  auto s = str(j, k);
  require(!s.empty() && s.size() < 20 &&
              s.find_first_not_of("0123456789") == std::string::npos,
          "integer_string");
  try {
    return std::stoll(s);
  } catch (...) {
    throw std::runtime_error("integer_overflow");
  }
}
static std::string scalar(int64_t n) { return std::to_string(n); }
static std::string policy_digest(const Config &c) {
  std::string s;
  for (auto &v : c.exemptions)
    s += v + "\n";
  return sha(s);
}
J Engine::proposal(const std::string &node, const J &j) {
  require(conf.role == "master" && conf.members.count(node),
          "unregistered_source");
  keys(j,
       "ip scope ban_id reason source origin layer waf generation boot decided "
       "expires deadline proposal_seq accepted applied seq event_id");
  require(str(j, "source") == node && num(j, "layer") == 3 &&
              str(j, "origin") == "local" && str(j, "scope").empty(),
          "proposal_identity");
  auto ip = ip_text(ip_parse(str(j, "ip")));
  require(ip == str(j, "ip"), "noncanonical_ip");
  auto id = str(j, "event_id");
  require(id.size() == 32 &&
              id.find_first_not_of("0123456789abcdef") == std::string::npos &&
              id == str(j, "ban_id"),
          "proposal_id");
  require(reason_valid(str(j, "reason")), "proposal_reason");
  int64_t seq = integer(j, "seq"), decided = integer(j, "decided"),
          expires = integer(j, "expires"), high = 0;
  require(seq > 0 && expires > decided && expires - decided <= 2592000000LL &&
              decided <= utc() + conf.skew_ms,
          "proposal_time");
  auto digest = sha(dump(j));
  {
    Statement q(db, "SELECT seq FROM origin_high WHERE node=?");
    q.bind(1, node);
    if (q.row())
      high = q.integer(0);
  }
  if (seq <= high) {
    Statement q(
        db,
        "SELECT digest,revision FROM origin_receipts WHERE node=? AND seq=?");
    q.bind(1, node);
    q.bind(2, seq);
    require(q.row() && q.text(0) == digest, "proposal_replay_conflict");
    auto out = object();
    set(out, "revision", scalar(q.integer(1)));
    return out;
  }
  require(seq == high + 1 && count("origin_receipts") < 200000,
          "proposal_sequence_or_capacity");
  sql("BEGIN IMMEDIATE");
  int64_t revision = std::stoll(meta("revision", "1"));
  try {
    bool allowed =
        expires > utc() + conf.skew_ms && !exempt(conf, ip_parse(ip));
    {
      Statement q(db, "SELECT utc FROM fences WHERE ip=?");
      q.bind(1, ip);
      if (q.row() && decided <= q.integer(0))
        allowed = false;
    }
    if (allowed) {
      J previous;
      Statement q(db, "SELECT value FROM globals WHERE ip=?");
      q.bind(1, ip);
      if (q.row())
        previous = parse(q.text(0));
      J r;
      if (previous && integer(previous, "expires") > utc()) {
        r = previous;
        if (expires < integer(r, "expires")) {
          set(r, "expires", scalar(expires));
          revision++;
        }
      } else {
        require(count("globals") < BAN_CAPACITY, "global_capacity");
        r = object();
        set(r, "ip", ip);
        set(r, "ban_id", id);
        set(r, "source", node);
        set(r, "reason", str(j, "reason"));
        set(r, "decided", scalar(decided));
        set(r, "expires", scalar(expires));
        revision++;
      }
      Statement s(db, "INSERT INTO globals VALUES(?,?) ON CONFLICT(ip) DO "
                      "UPDATE SET value=excluded.value");
      s.bind(1, ip);
      s.bind(2, dump(r));
      s.done();
      audit("CLUSTER_ACCEPTED", r);
    }
    Statement h(db, "INSERT INTO origin_high VALUES(?,?) ON CONFLICT(node) DO "
                    "UPDATE SET seq=excluded.seq");
    h.bind(1, node);
    h.bind(2, seq);
    h.done();
    Statement receipt(db, "INSERT INTO origin_receipts VALUES(?,?,?,?)");
    receipt.bind(1, node);
    receipt.bind(2, seq);
    receipt.bind(3, digest);
    receipt.bind(4, revision);
    receipt.done();
    meta_set("revision", scalar(revision));
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
  publish_snapshot();
  project();
  auto out = object();
  set(out, "revision", scalar(revision));
  return out;
}
void Engine::publish_snapshot() {
  require(conf.role == "master", "authority_required");
  int64_t revision = std::stoll(meta("revision", "1"));
  Statement q(db, "SELECT ip,value FROM globals ORDER BY ip");
  std::vector<std::string> expired;
  auto records = own(json_object_new_array());
  while (q.row()) {
    auto r = parse(q.text(1));
    if (integer(r, "expires") <= utc())
      expired.push_back(q.text(0));
    else
      json_object_array_add(records.get(), json_object_get(r.get()));
  }
  if (!expired.empty()) {
    sql("BEGIN IMMEDIATE");
    try {
      for (auto &ip : expired) {
        Statement d(db, "DELETE FROM globals WHERE ip=?");
        d.bind(1, ip);
        d.done();
      }
      meta_set("revision", scalar(++revision));
      sql("COMMIT");
    } catch (...) {
      sql("ROLLBACK");
      throw;
    }
  }
  if (meta("published_revision") == scalar(revision) &&
      !meta("snapshot").empty())
    return;
  auto payload = object();
  set(payload, "version", 1);
  set(payload, "cluster", conf.cluster);
  set(payload, "epoch", conf.epoch);
  set(payload, "revision", scalar(revision));
  set(payload, "generated", scalar(utc()));
  set(payload, "allowlist_digest", policy_digest(conf));
  set(payload, "bans", records);
  auto members = own(json_object_new_array());
  for (auto &node : conf.members)
    json_object_array_add(members.get(), json_object_new_string(node.c_str()));
  set(payload, "members", members);
  auto fences = own(json_object_new_array());
  Statement f(db, "SELECT ip,utc FROM fences ORDER BY ip");
  while (f.row()) {
    auto r = object();
    set(r, "ip", f.text(0));
    set(r, "time", scalar(f.integer(1)));
    json_object_array_add(fences.get(), json_object_get(r.get()));
  }
  set(payload, "fences", fences);
  auto text = dump(payload), signed_text = sign_snapshot(conf, text);
  require(signed_text.size() <= BAN_MAX_FRAME, "snapshot_capacity");
  sql("BEGIN IMMEDIATE");
  try {
    meta_set("snapshot", signed_text);
    meta_set("snapshot_digest", sha(text));
    meta_set("published_revision", scalar(revision));
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
}
J Engine::snapshot() {
  publish_snapshot();
  return parse(meta("snapshot"));
}
void Engine::apply_snapshot(const std::string &envelope) {
  auto text = verify_snapshot(conf, envelope), digest = sha(text);
  auto j = parse(text);
  keys(j, "version cluster epoch revision generated allowlist_digest bans "
          "members fences");
  require(num(j, "version") == 1 && str(j, "cluster") == conf.cluster &&
              str(j, "epoch") == conf.epoch,
          "snapshot_identity");
  auto revision = integer(j, "revision");
  auto highest = std::stoll(meta("highest_revision", "0"));
  require(revision >= highest &&
              (revision != highest || meta("highest_digest") == digest),
          "snapshot_high_watermark");
  require(revision >= accepted_revision &&
              integer(j, "generated") <= utc() + conf.skew_ms,
          "snapshot_revision_or_clock");
  require(str(j, "allowlist_digest") == policy_digest(conf),
          "cluster_allowlist_mismatch");
  if (revision == accepted_revision) {
    require(meta("accepted_digest") == digest, "snapshot_revision_conflict");
    Statement pending(db,
                      "SELECT COUNT(*) FROM records WHERE "
                      "json_extract(value,'$.origin')='local' AND "
                      "json_extract(value,'$.layer')=3 AND "
                      "CAST(json_extract(value,'$.accepted') AS INTEGER)>0 AND "
                      "CAST(json_extract(value,'$.accepted') AS INTEGER)<=?");
    pending.bind(1, revision);
    require(pending.row(), "pending_local_count");
    if (!pending.integer(0)) {
      reconcile();
      project();
      return;
    }
  }
  auto members = get(j, "members");
  require(json_object_is_type(members.get(), json_type_array),
          "snapshot_members");
  std::set<std::string> m;
  for (size_t i = 0; i < json_object_array_length(members.get()); i++) {
    auto *v = json_object_array_get_idx(members.get(), i);
    require(json_object_is_type(v, json_type_string) &&
                m.insert(json_object_get_string(v)).second,
            "snapshot_members");
  }
  require(m == conf.members, "membership_mismatch");
  auto bans = get(j, "bans"), fences = get(j, "fences");
  require(json_object_is_type(bans.get(), json_type_array) &&
              json_object_array_length(bans.get()) <= BAN_CAPACITY &&
              json_object_is_type(fences.get(), json_type_array) &&
              json_object_array_length(fences.get()) <= 65536,
          "snapshot_bounds");
  std::map<std::string, J> incoming;
  for (size_t i = 0; i < json_object_array_length(bans.get()); i++) {
    auto r = own(json_object_get(json_object_array_get_idx(bans.get(), i)));
    keys(r, "ip ban_id source reason decided expires");
    auto ip = ip_text(ip_parse(str(r, "ip"))), id = str(r, "ban_id");
    require(ip == str(r, "ip") && id.size() == 32 &&
                id.find_first_not_of("0123456789abcdef") == std::string::npos &&
                conf.members.count(str(r, "source")) &&
                reason_valid(str(r, "reason")),
            "snapshot_record");
    require(integer(r, "expires") > integer(r, "decided") &&
                integer(r, "expires") - integer(r, "decided") <= 2592000000LL &&
                incoming.emplace(ip, r).second,
            "snapshot_duplicate_or_expiry");
    require(!exempt(conf, ip_parse(ip)), "snapshot_exempt_ip");
  }
  require(count("records") + (int64_t)incoming.size() <= BAN_CAPACITY * 2,
          "snapshot_preflight_capacity");
  std::map<std::string, J> previous;
  {
    Statement q(db, "SELECT value FROM records WHERE key LIKE 'cluster|%'");
    while (q.row()) {
      auto r = parse(q.text(0));
      previous[str(r, "ip")] = r;
    }
  }
  sql("BEGIN IMMEDIATE");
  try {
    // Persist the entire desired set before any kernel mutation.
    meta_set("pending_snapshot", envelope);
    meta_set("highest_revision", scalar(revision));
    meta_set("highest_digest", digest);
    for (size_t i = 0; i < json_object_array_length(fences.get()); i++) {
      auto f = own(json_object_get(json_object_array_get_idx(fences.get(), i)));
      keys(f, "ip time");
      auto ip = ip_text(ip_parse(str(f, "ip")));
      auto time = integer(f, "time");
      require(time <= utc() + conf.skew_ms, "fence_clock");
      auto age = std::max<int64_t>(0, utc() - time - conf.skew_ms);
      auto now = (int64_t)ban_now();
      auto cutoff = age >= now / 1000000 ? 0 : now - age * 1000000;
      Statement q(db, "INSERT INTO fences VALUES(?,?,?) ON CONFLICT(ip) DO "
                      "UPDATE SET boot=CASE WHEN excluded.utc>utc THEN "
                      "MAX(boot,excluded.boot) ELSE boot END,utc=MAX(utc,excluded.utc)");
      q.bind(1, ip);
      q.bind(2, time);
      q.bind(3, cutoff);
      q.done();
      Statement evidence(db, "DELETE FROM evidence WHERE ip=? AND observed<=?");
      evidence.bind(1, ip); evidence.bind(2, cutoff); evidence.done();
    }
    std::vector<std::string> remove;
    Statement q(db, "SELECT key,value FROM records");
    while (q.row()) {
      auto r = parse(q.text(1));
      auto ip = str(r, "ip");
      Statement fence(db, "SELECT utc FROM fences WHERE ip=?");
      fence.bind(1, ip);
      bool fenced = fence.row() && integer(r, "decided") <= fence.integer(0);
      if (num(r, "layer") != 3 && !fenced)
        continue;
      bool global = str(r, "origin") == "cluster";
      int64_t accepted = integer(r, "accepted");
      if (global || fenced || (accepted && accepted <= revision))
        remove.push_back(q.text(0));
    }
    for (auto &key : remove) {
      auto old = record(key);
      if (old && !incoming.count(str(old, "ip")))
        audit(integer(old, "expires") <= utc() ? "EXPIRED" : "CLUSTER_REMOVED",
              old);
      Statement d(db, "DELETE FROM records WHERE key=?");
      d.bind(1, key);
      d.done();
    }
    for (auto &entry : incoming) {
      auto r = parse(dump(entry.second));
      int64_t remaining =
          std::max<int64_t>(0, std::min(integer(r, "expires") - integer(r, "decided"),
                                      integer(r, "expires") - utc() - conf.skew_ms));
      if (!remaining)
        continue;
      auto old = previous.count(entry.first) ? previous[entry.first] : J{};
      int64_t deadline = (int64_t)ban_now() + remaining * 1000000;
      if (old && str(old, "ban_id") == str(r, "ban_id"))
        deadline = std::min(deadline, integer(old, "deadline"));
      set(r, "scope", std::string(""));
      set(r, "origin", std::string("cluster"));
      set(r, "layer", 3);
      set(r, "waf", 0);
      set(r, "generation", scalar(generation));
      set(r, "deadline", scalar(deadline));
      set(r, "boot", conf.boot);
      set(r, "proposal_seq", std::string("0"));
      set(r, "accepted", scalar(revision));
      bool unchanged = old && str(old, "ban_id") == str(r, "ban_id") &&
                       integer(old, "expires") == integer(r, "expires");
      if (unchanged) {
        set(r, "deadline", str(old, "deadline"));
        set(r, "generation", str(old, "generation"));
      }
      set(r, "applied", unchanged ? num(old, "applied") : 0);
      save_record("cluster|" + entry.first, r);
      if (!unchanged)
        audit("CLUSTER_PREPARE", r);
    }
    require(count("records") <= BAN_CAPACITY, "snapshot_active_capacity");
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
  reconcile();
  project();
  accepted_revision = revision;
  sql("BEGIN IMMEDIATE");
  try {
    meta_set("accepted_revision", scalar(revision));
    meta_set("accepted_digest", digest);
    meta_set("pending_snapshot", "");
    sql("COMMIT");
  } catch (...) {
    sql("ROLLBACK");
    throw;
  }
}
J Engine::bridge(const std::string &node, const std::string &operation,
                 const J &request) {
  require(conf.role == "master", "master_required");
  if (node == "__control__") {
    auto admin = parse(dump(request));
    set(admin, "operation", operation);
    return query(admin);
  }
  require(conf.members.count(node), "node_not_registered");
  if (operation == "proposals")
    return proposal(node, request);
  if (operation == "snapshot")
    return snapshot();
  if (operation == "results") {
    keys(request, "revision digest state");
    int64_t revision = integer(request, "revision"),
            current = std::stoll(meta("revision", "1"));
    auto digest = str(request, "digest"), state = str(request, "state");
    require(revision == current && digest == meta("snapshot_digest") &&
                (state == "applied" || state == "failed"),
            "result_revision_conflict");
    Statement q(
        db,
        "INSERT INTO results VALUES(?,?,?,?) ON CONFLICT(node) DO UPDATE SET "
        "revision=excluded.revision,digest=excluded.digest,state=excluded."
        "state");
    q.bind(1, node);
    q.bind(2, revision);
    q.bind(3, digest);
    q.bind(4, state);
    q.done();
    meta_set("result_seen:"+node,scalar(utc()));
    return status();
  }
  throw std::runtime_error("unknown_bridge_operation");
}
void Engine::cluster_cycle() {
  Config settings;
  std::vector<std::pair<int64_t, std::string>> outbox;
  {
    std::lock_guard<std::mutex> lock(mutex);
    settings = conf;
    Statement q(
        db,
        "SELECT seq,value FROM outbox WHERE accepted=0 ORDER BY seq LIMIT 32");
    while (q.row())
      outbox.push_back({q.integer(0), q.text(1)});
  }
  try {
    struct timex clock_state{};
    require(adjtimex(&clock_state) != TIME_ERROR &&
                !(clock_state.status & STA_UNSYNC),
            "CLOCK_UNCERTAIN");
    for (auto &item : outbox) {
      J response;
      if (settings.role == "master") {
        std::lock_guard<std::mutex> lock(mutex);
        response = proposal(settings.node, parse(item.second));
      } else {
        auto result =
            http(settings, "/_scdn_sync/v1/ban/proposals", item.second);
        require(result.first == 200, "proposal_transport");
        response = parse(result.second);
      }
      int64_t revision = integer(response, "revision");
      std::lock_guard<std::mutex> lock(mutex);
      sql("BEGIN IMMEDIATE");
      try {
        Statement q(db, "UPDATE outbox SET accepted=? WHERE seq=?");
        q.bind(1, revision);
        q.bind(2, item.first);
        q.done();
        Statement records(db, "SELECT key,value FROM records");
        std::vector<std::pair<std::string, J>> update;
        while (records.row()) {
          auto r = parse(records.text(1));
          if (str(r, "origin") == "local" &&
              integer(r, "proposal_seq") == item.first)
            update.push_back({records.text(0), r});
        }
        for (auto &r : update) {
          set(r.second, "accepted", scalar(revision));
          save_record(r.first, r.second);
        }
        sql("COMMIT");
      } catch (...) {
        sql("ROLLBACK");
        throw;
      }
    }
    std::string envelope;
    if (settings.role == "master") {
      std::lock_guard<std::mutex> lock(mutex);
      envelope = dump(snapshot());
    } else {
      auto result = http(settings, "/_scdn_sync/v1/ban/snapshot", "");
      require(result.first == 200, "snapshot_transport");
      envelope = result.second;
    }
    J result = object();
    {
      std::lock_guard<std::mutex> lock(mutex);
      apply_snapshot(envelope);
      set(result, "revision", meta("accepted_revision"));
      set(result, "digest", meta("accepted_digest"));
      set(result, "state", std::string("applied"));
      Statement gc(db, "DELETE FROM outbox WHERE accepted>0 AND accepted<=?");
      gc.bind(1, accepted_revision);
      gc.done();
      sync_error.clear();
    }
    if (settings.role == "master") {
      std::lock_guard<std::mutex> lock(mutex);
      bridge(settings.node, "results", result);
    } else {
      auto response =
          http(settings, "/_scdn_sync/v1/ban/results", dump(result));
      require(response.first == 200, "result_transport");
    }
  } catch (const std::exception &e) {
    std::lock_guard<std::mutex> lock(mutex);
    sync_error = e.what();
  }
}
} // namespace ban
