#include "log_sync.hpp"
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <glob.h>
#include <mutex>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace logs {
Input::~Input() {
  if (gz)
    gzclose(gz);
  if (fd >= 0)
    close(fd);
}
std::string Input::at(uint64_t offset, size_t count) {
  need(offset <= INT64_MAX, SOURCE);
  if (archive) {
    if (offset < cache_offset || offset > cache_offset + cache.size()) {
      need(gzseek(gz, static_cast<z_off_t>(offset), SEEK_SET) >= 0, SOURCE);
      pos = offset;
      cache_offset = offset;
      cache.clear();
    }
    if (offset - cache_offset > 2 * 1024 * 1024) {
      size_t remove = static_cast<size_t>(offset - cache_offset) - 64;
      cache.erase(0, remove);
      cache_offset += remove;
    }
    size_t begin = static_cast<size_t>(offset - cache_offset);
    while (cache.size() < begin + count) {
      char buffer[65536];
      int n = gzread(gz, buffer, sizeof(buffer));
      need(n >= 0, SOURCE);
      if (!n) {
        int error = 0;
        gzerror(gz, &error);
        need(error == Z_OK || error == Z_STREAM_END, SOURCE);
        break;
      }
      cache.append(buffer, n);
      pos += n;
    }
    return cache.substr(begin, std::min(count, cache.size() - begin));
  }
  std::string result(count, '\0');
  if (archive) {
    if (pos != offset) {
      need(gzseek(gz, static_cast<z_off_t>(offset), SEEK_SET) >= 0, SOURCE);
      pos = offset;
    }
    int n = gzread(gz, &result[0], static_cast<unsigned>(count));
    need(n >= 0, SOURCE);
    if (!n) {
      int error = 0;
      gzerror(gz, &error);
      need(error == Z_OK || error == Z_STREAM_END, SOURCE);
    }
    result.resize(n);
    pos += n;
  } else {
    ssize_t n;
    do {
      n = pread(fd, &result[0], count, static_cast<off_t>(offset));
    } while (n < 0 && errno == EINTR);
    need(n >= 0, SOURCE);
    result.resize(n);
  }
  return result;
}
static J empty_state(const Config &c) {
  auto s = obj();
  put(s, "version", uint64_t(1));
  put(s, "node", c.node);
  put(s, "binding", c.binding);
  put(s, "seq", uint64_t(0));
  put(s, "round_robin", uint64_t(0));
  put(s, "files", obj());
  return s;
}
Engine::Engine(const std::string &path) : conf(config_read(path)) {
  directory.value = safe_open(conf.state, O_RDONLY | O_DIRECTORY);
  need(directory.value >= 0, IO);
  struct stat st{};
  need(!fstat(directory.value, &st) && st.st_uid == geteuid() &&
           !(st.st_mode & 077),
       CONFIG);
  lock.value =
      openat(directory.value, "sync.lock",
             O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
  need(lock.value >= 0 && !fstat(lock.value, &st) && S_ISREG(st.st_mode) &&
           st.st_uid == geteuid() && !(st.st_mode & 077),
       IO);
}
J Engine::load(const char *name, bool optional) {
  Fd fd(openat(directory.value, name,
               O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
  if (fd.value < 0) {
    need(optional && errno == ENOENT, IO);
    return {};
  }
  struct stat st{};
  need(!fstat(fd.value, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
           !(st.st_mode & 077) && st.st_size >= 0 &&
           static_cast<uint64_t>(st.st_size) <= 128 * 1024 * 1024,
       STATE);
  std::string raw;
  char bytes[8192];
  for (;;) {
    ssize_t n = read(fd.value, bytes, sizeof(bytes));
    if (n < 0 && errno == EINTR)
      continue;
    need(n >= 0, IO);
    if (!n)
      break;
    need(raw.size() + static_cast<size_t>(n) <= 128 * 1024 * 1024, STATE);
    raw.append(bytes, n);
  }
  auto envelope = parse(raw);
  auto payload = text(envelope, "payload");
  need(sha(payload) == text(envelope, "sha256"), STATE);
  return parse(payload);
}
void Engine::save(const char *name, const J &value) {
  auto envelope = obj();
  auto payload = dump(value);
  put(envelope, "payload", payload);
  put(envelope, "sha256", sha(payload));
  auto raw = dump(envelope) + "\n";
  need(raw.size() <= 128 * 1024 * 1024, CAPACITY);
  std::string temp = std::string(name) + ".new";
  /* Fixed scratch names keep interrupted writes bounded. They are never
   * trusted as committed state and cannot follow links. */
  Fd fd(openat(directory.value, temp.c_str(),
               O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600));
  need(fd.value >= 0, IO);
  struct stat st{};
  need(!fstat(fd.value, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
           !(st.st_mode & 077) && st.st_nlink == 1,
       IO);
  need(!ftruncate(fd.value, 0), IO);
  size_t done = 0;
  while (done < raw.size()) {
    ssize_t n = write(fd.value, raw.data() + done, raw.size() - done);
    if (n < 0 && errno == EINTR)
      continue;
    need(n > 0, IO);
    done += n;
  }
  need(!fdatasync(fd.value), IO);
  need(!renameat(directory.value, temp.c_str(), directory.value, name), IO);
  need(!fsync(directory.value), IO);
}
void Engine::erase(const char *name) {
  need(!unlinkat(directory.value, name, 0) || errno == ENOENT, IO);
  need(!fsync(directory.value), IO);
}
static std::string file_key(const std::string &source, const struct stat &st) {
  return source + ":" + std::to_string(st.st_dev) + ":" +
         std::to_string(st.st_ino);
}
static std::string anchor(Input &in, uint64_t offset) {
  size_t n = std::min<uint64_t>(offset, 64);
  return sha(in.at(offset - n, n));
}
static bool current(const J &entry, Input &input, const struct stat &st) {
  auto offset = number(entry, "offset");
  if (!input.archive && static_cast<uint64_t>(st.st_size) < offset)
    return false;
  return anchor(input, offset) == text(entry, "anchor");
}
J Engine::prepare(J state, scdn_log_sync_result &result) {
  auto next = copy(state), files = get(next, "files");
  need(number(state, "version") == 1 &&
           text(state, "binding") == conf.binding &&
           text(state, "node") == conf.node,
       STATE);
  std::vector<std::pair<std::string, const Source *>> paths;
  std::set<std::string> discovered;
  for (auto &source : conf.sources)
    for (auto &pattern : source.paths) {
      glob_t found{};
      int rc = glob(pattern.c_str(), GLOB_NOSORT, nullptr, &found);
      if (rc != 0 && rc != GLOB_NOMATCH) {
        globfree(&found);
        throw Failure(SOURCE);
      }
      if (found.gl_pathc > conf.max_files) {
        globfree(&found);
        throw Failure(CAPACITY);
      }
      for (size_t i = 0; i < found.gl_pathc; i++) {
        std::string path = found.gl_pathv[i];
        if (discovered.insert(source.id + "\n" + path).second)
          paths.emplace_back(path, &source);
      }
      globfree(&found);
      need(paths.size() <= conf.max_files, CAPACITY);
    }
  std::sort(paths.begin(), paths.end(),
            [](auto &a, auto &b) { return a.first < b.first; });
  std::map<std::string, std::pair<struct stat, const Source *>> available;
  std::set<std::string> live;
  for (auto &item : paths) {
    need(item.second->id == "telemetry" ||
             item.first.compare(0, conf.state.size() + 1, conf.state + "/") !=
                 0,
         CONFIG);
    Fd fd(safe_open(item.first, O_RDONLY));
    need(fd.value >= 0, SOURCE);
    struct stat st{};
    need(!fstat(fd.value, &st), SOURCE);
    if (!S_ISREG(st.st_mode))
      continue;
    auto key = file_key(item.second->id, st);
    live.insert(key);
    auto committed = get(files, key.c_str(), false);
    if (committed && flag(committed, "archive") &&
        (number(committed, "skip_archive") ||
         (number(committed, "sealed") &&
          number(committed, "sealed_size") ==
              static_cast<uint64_t>(st.st_size) &&
          number(committed, "sealed_mtime") ==
              static_cast<uint64_t>(st.st_mtim.tv_sec) &&
          number(committed, "sealed_ns") ==
              static_cast<uint64_t>(st.st_mtim.tv_nsec))))
      continue;
    available[key] = {st, item.second};
    auto previous = inputs.find(key);
    if (previous != inputs.end())
      previous->second->path = item.first;
    else {
      auto input = std::make_shared<Input>();
      input->key = key;
      input->path = item.first;
      input->source = item.second->id;
      input->archive = item.first.size() >= 3 &&
                       item.first.substr(item.first.size() - 3) == ".gz";
      input->fd = fd.value;
      fd.value = -1;
      if (input->archive) {
        int duplicate = dup(input->fd);
        need(duplicate >= 0, SOURCE);
        input->gz = gzdopen(duplicate, "rb");
        if (!input->gz) {
          close(duplicate);
          throw Failure(SOURCE);
        }
      }
      inputs.emplace(key, input);
    }
  }
  /* Open handles let renamed/unlinked active files drain until EOF, even
   * between discovery scans. Restart still requires retained source files. */
  for (auto &item : inputs)
    if (!live.count(item.first)) {
      struct stat st{};
      need(!fstat(item.second->fd, &st), SOURCE);
      auto source =
          std::find_if(conf.sources.begin(), conf.sources.end(),
                       [&](auto &s) { return s.id == item.second->source; });
      if (source != conf.sources.end())
        available[item.first] = {st, &*source};
    }
  auto events = arr();
  size_t bytes = 0;
  bool changed = false;
  auto baselines = get(next, "tail_baselines", false);
  if (!baselines) {
    baselines = obj();
    put(next, "tail_baselines", baselines);
  }
  for (auto &source : conf.sources)
    if (source.start == "tail" && !number(baselines, source.id.c_str())) {
      for (auto &item : available)
        if (item.second.second->id == source.id) {
          auto &input = *inputs.at(item.first);
          auto &st = item.second.first;
          auto entry = obj();
          put(entry, "generation", random_id());
          put(entry, "source", source.id);
          put(entry, "path", input.path);
          json_object_object_add(entry.get(), "archive",
                                 json_object_new_boolean(input.archive));
          uint64_t begin =
              input.archive ? 0 : static_cast<uint64_t>(st.st_size);
          put(entry, "offset", begin);
          put(entry, "anchor", anchor(input, begin));
          put(entry, "skip_archive", input.archive ? uint64_t(1) : uint64_t(0));
          put(entry, "discard_partial",
              !input.archive && begin > 0 && input.at(begin - 1, 1) != "\n"
                  ? uint64_t(1)
                  : uint64_t(0));
          put(files, item.first.c_str(), entry);
        }
      put(baselines, source.id.c_str(), uint64_t(1));
      changed = true;
    }
  std::vector<std::string> keys;
  for (auto &item : available)
    keys.push_back(item.first);
  size_t start = keys.empty() ? 0 : number(next, "round_robin") % keys.size();
  for (size_t step = 0; step < keys.size(); step++) {
    auto &key = keys[(start + step) % keys.size()];
    auto &input = *inputs.at(key);
    auto &st = available.at(key).first;
    auto &source = *available.at(key).second;
    auto entry = get(files, key.c_str(), false);
    if (!entry && input.archive) {
      std::string plain = input.path.substr(0, input.path.size() - 3), adopt;
      json_object_object_foreach(files.get(), old_name, old_value) {
        auto old = own(json_object_get(old_value));
        if (!live.count(old_name) && text(old, "source") == source.id &&
            text(old, "path") == plain && !flag(old, "archive") &&
            current(old, input, st)) {
          adopt = old_name;
          entry = copy(old);
          break;
        }
      }
      if (!adopt.empty())
        json_object_object_del(files.get(), adopt.c_str());
    }
    if (entry && !current(entry, input, st)) {
      entry = {};
      changed = true;
    }
    if (!entry) {
      need(json_object_object_length(files.get()) <
               static_cast<int>(conf.max_files),
           CAPACITY);
      entry = obj();
      put(entry, "generation", random_id());
      put(entry, "source", source.id);
      uint64_t begin = 0;
      put(entry, "offset", begin);
      put(entry, "anchor", anchor(input, begin));
      put(entry, "discard_partial", uint64_t(0));
      changed = true;
    }
    put(entry, "path", input.path);
    json_object_object_add(entry.get(), "archive",
                           json_object_new_boolean(input.archive));
    put(files, key.c_str(), entry);
    if (number(entry, "skip_archive"))
      continue;
    uint64_t offset = number(entry, "offset");
    size_t per_file = 0;
    while (json_object_array_length(events.get()) < conf.batch_records &&
           per_file < 64) {
      std::string raw;
      while (raw.size() < conf.line_bytes) {
        size_t wanted = std::min<size_t>(4096, conf.line_bytes - raw.size());
        auto part = input.at(offset + raw.size(), wanted);
        auto end = part.find('\n');
        if (end != std::string::npos) {
          raw.append(part, 0, end + 1);
          break;
        }
        raw += part;
        if (part.size() < wanted)
          break;
      }
      if (raw.empty()) {
        if (input.archive) {
          put(entry, "sealed", uint64_t(1));
          put(entry, "sealed_size", uint64_t(st.st_size));
          put(entry, "sealed_mtime", uint64_t(st.st_mtim.tv_sec));
          put(entry, "sealed_ns", uint64_t(st.st_mtim.tv_nsec));
          changed = true;
        }
        break;
      }
      auto nl = raw.find('\n');
      bool terminated = nl != std::string::npos;
      if (terminated)
        raw.resize(nl + 1);
      bool fragment = !terminated && raw.size() == conf.line_bytes;
      if (!terminated && !fragment && !input.archive)
        break;
      uint64_t end = offset + raw.size();
      need(end >= offset, SOURCE);
      if (number(entry, "discard_partial")) {
        offset = end;
        changed = true;
        if (terminated)
          put(entry, "discard_partial", uint64_t(0));
        continue;
      }
      auto event = obj();
      auto generation = text(entry, "generation");
      put(event, "event_id",
          sha(conf.node + "\n" + source.id + "\n" + generation + "\n" +
              std::to_string(offset) + "\n" + sha(raw)));
      put(event, "timestamp", now());
      put(event, "node", conf.node);
      put(event, "source", source.id);
      put(event, "path", input.path);
      put(event, "kind", source.kind);
      put(event, "generation", generation);
      put(event, "offset", offset);
      put(event, "end_offset", end);
      put(event, "raw_base64", base64(raw));
      put(event, "terminated", terminated ? uint64_t(1) : uint64_t(0));
      bool continuation = number(entry, "in_fragment") != 0;
      put(event, "fragment",
          fragment || continuation ? uint64_t(1) : uint64_t(0));
      put(event, "archive", input.archive ? uint64_t(1) : uint64_t(0));
      std::string message = raw;
      if (terminated)
        message.pop_back();
      if (!message.empty() && message.back() == '\r')
        message.pop_back();
      bool valid = utf8(message);
      put(event, "message", valid ? message : "");
      put(event, "format", valid ? "text" : "binary");
      put(event, "fields_json", "");
      put(event, "normalized_json", "");
      bool invalid_record = (source.kind == "access" || source.kind == "ban") &&
                            !fragment && !continuation;
      if (valid && !fragment && !continuation && source.format != "text")
        try {
          auto fields = parse(message);
          if (json_object_is_type(fields.get(), json_type_object)) {
            put(event, "fields_json", dump(fields));
            put(event, "format", "json");
            auto normalized =
                normalize(conf, source, fields, text(event, "event_id"));
            if (normalized) {
              invalid_record = false;
              put(event, "normalized_json", dump(normalized));
              put(event, "event_id", text(normalized, "event_id"));
            }
          }
        } catch (const std::exception &) {
        }
      auto size = dump(event).size();
      need(size <= conf.batch_bytes, CAPACITY);
      if (bytes + size > conf.batch_bytes)
        break;
      if (invalid_record)
        put(next, "invalid_records", number(next, "invalid_records") + 1);
      put(entry, "in_fragment",
          terminated                 ? uint64_t(0)
          : fragment || continuation ? uint64_t(1)
                                     : uint64_t(0));
      bytes += size;
      json_object_array_add(events.get(), json_object_get(event.get()));
      offset = end;
      per_file++;
      changed = true;
    }
    put(entry, "offset", offset);
    put(entry, "anchor", anchor(input, offset));
    put(next, "round_robin", uint64_t((start + step + 1) % keys.size()));
    if (json_object_array_length(events.get()) >= conf.batch_records ||
        bytes + conf.line_bytes * 4 + 8192 > conf.batch_bytes)
      break;
  }
  need(json_object_object_length(files.get()) <=
           static_cast<int>(conf.max_files),
       CAPACITY);
  result.files = json_object_object_length(files.get());
  /* Release exhausted missing files, with committed offsets retained. */
  for (auto it = inputs.begin(); it != inputs.end();) {
    auto entry = get(files, it->first.c_str(), false);
    if (entry && (number(entry, "sealed") || number(entry, "skip_archive")))
      it = inputs.erase(it);
    else if (!live.count(it->first) && entry &&
             it->second->at(number(entry, "offset"), 1).empty())
      it = inputs.erase(it);
    else
      ++it;
  }
  if (!changed)
    return {};
  put(next, "seq", number(state, "seq") + 1);
  if (!json_object_array_length(events.get())) {
    save("state.json", next);
    return {};
  }
  put(next, "confirmed_events",
      number(state, "confirmed_events") +
          json_object_array_length(events.get()));
  auto pending = obj();
  put(pending, "binding", conf.binding);
  put(pending, "base_digest", sha(dump(state)));
  put(pending, "next", next);
  put(pending, "events", events);
  put(pending, "acked", obj());
  put(pending, "batch", sha(dump(events)));
  save("pending.json", pending);
  return pending;
}
bool Engine::deliver(const J &pending, scdn_log_sync_result &result) {
  auto events = get(pending, "events"), acked = get(pending, "acked");
  need(json_object_is_type(events.get(), json_type_array) &&
           json_object_array_length(events.get()) >= 1 &&
           json_object_array_length(events.get()) <= 4096 &&
           sha(dump(events)) == text(pending, "batch"),
       STATE);
  result.pending = json_object_array_length(events.get());
  bool complete = true;
  for (auto &sink : conf.sinks) {
    if (number(acked, sink.id.c_str()))
      continue;
    try {
      send(conf, sink, events, text(pending, "batch"));
      put(acked, sink.id.c_str(), uint64_t(1));
      save("pending.json", pending);
      result.sent_requests++;
    } catch (const Failure &error) {
      complete = false;
      result.error = error.code;
    }
  }
  return complete;
}
int Engine::cycle(scdn_log_sync_result &result) {
  if (flock(lock.value, LOCK_EX | LOCK_NB)) {
    need(errno == EWOULDBLOCK || errno == EAGAIN, IO);
    return LOCKED;
  }
  struct Unlock {
    int fd;
    ~Unlock() { flock(fd, LOCK_UN); }
  } unlock{lock.value};
  auto state = load("state.json", true);
  if (!state) {
    state = empty_state(conf);
    save("state.json", state);
  }
  need(text(state, "binding") == conf.binding &&
           text(state, "node") == conf.node && number(state, "version") == 1,
       STATE);
  auto pending = load("pending.json", true);
  if (pending) {
    need(text(pending, "binding") == conf.binding, STATE);
    auto next = get(pending, "next");
    if (number(state, "seq") == number(next, "seq")) {
      need(dump(state) == dump(next), STATE);
      erase("pending.json");
      pending = {};
    } else
      need(number(next, "seq") == number(state, "seq") + 1 &&
               text(pending, "base_digest") == sha(dump(state)),
           STATE);
  }
  if (!pending)
    pending = prepare(state, result);
  if (!pending)
    return OK;
  result.pending = json_object_array_length(get(pending, "events").get());
  if (monotonic_ms() < retry_at)
    return BACKEND;
  if (!deliver(pending, result)) {
    retry_at = monotonic_ms() + conf.retry_ms;
    return result.error ? result.error : BACKEND;
  }
  auto next = get(pending, "next");
  save("state.json", next);
  erase("pending.json");
  /* Only closed, completely acknowledged internal telemetry segments may be
   * reclaimed. User logs are never removed by this module. */
  auto files = get(next, "files");
  std::vector<std::string> reclaim;
  json_object_object_foreach(files.get(), key, value) {
    auto entry = own(json_object_get(value));
    auto path = text(entry, "path");
    auto prefix = conf.state + "/telemetry-";
    bool owned_segment =
        path.size() == prefix.size() + 32 + 6 &&
        path.compare(0, prefix.size(), prefix) == 0 &&
        path.compare(path.size() - 6, 6, ".jsonl") == 0 &&
        path.substr(prefix.size(), 32).find_first_not_of("0123456789abcdef") ==
            std::string::npos;
    if (text(entry, "source") == "telemetry" && owned_segment) {
      struct stat st{};
      if (lstat(path.c_str(), &st) < 0 && errno == ENOENT)
        reclaim.push_back(key);
      else if (S_ISREG(st.st_mode) &&
               static_cast<uint64_t>(st.st_size) == number(entry, "offset")) {
        need(!unlink(path.c_str()), IO);
        reclaim.push_back(key);
      }
    }
  }
  for (auto &key : reclaim) {
    json_object_object_del(files.get(), key.c_str());
    inputs.erase(key);
  }
  if (!reclaim.empty())
    save("state.json", next);
  result.confirmed = result.pending;
  result.pending = 0;
  result.files = json_object_object_length(get(next, "files").get());
  retry_at = 0;
  return OK;
}
} // namespace logs
extern "C" {
void *scdn_log_sync_create(const char *path, int *error) {
  try {
    auto *p = new logs::Engine(path);
    *error = 0;
    return p;
  } catch (const logs::Failure &e) {
    *error = e.code;
  } catch (...) {
    *error = logs::STATE;
  }
  return nullptr;
}
int scdn_log_sync_cycle(void *p, scdn_log_sync_result *result) {
  *result = {};
  try {
    result->error = static_cast<logs::Engine *>(p)->cycle(*result);
  } catch (const logs::Failure &e) {
    result->error = e.code;
  } catch (...) {
    result->error = logs::STATE;
  }
  return result->error;
}
void scdn_log_sync_destroy(void *p) { delete static_cast<logs::Engine *>(p); }
const char *scdn_log_sync_error(int code) {
  static const char *names[] = {
      "ok",     "configuration", "io",      "state_integrity",      "capacity",
      "source", "transport",     "backend", "owned_by_other_worker"};
  return code >= 0 && code < 9 ? names[code] : "internal";
}
}
