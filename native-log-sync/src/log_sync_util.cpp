#include "log_sync.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

namespace logs {
struct StrictJson {
  const std::string &s;
  size_t p = 0;
  unsigned depth = 0;
  void space() {
    while (p < s.size() &&
           (s[p] == ' ' || s[p] == '\r' || s[p] == '\n' || s[p] == '\t'))
      p++;
  }
  bool take(char c) {
    if (p < s.size() && s[p] == c) {
      p++;
      return true;
    }
    return false;
  }
  int hex() {
    if (p == s.size())
      return -1;
    char c = s[p++];
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  }
  int code() {
    int value = 0;
    for (unsigned i = 0; i < 4; i++) {
      int n = hex();
      if (n < 0)
        return -1;
      value = value * 16 + n;
    }
    return value;
  }
  bool string() {
    if (!take('"'))
      return false;
    while (p < s.size()) {
      unsigned char c = s[p++];
      if (c == '"')
        return true;
      if (c < 32)
        return false;
      if (c == '\\') {
        if (p == s.size())
          return false;
        char escaped = s[p++];
        if (escaped == 'u') {
          int n = code();
          if (n < 0)
            return false;
          if (n >= 0xd800 && n <= 0xdbff) {
            if (!take('\\') || !take('u'))
              return false;
            int low = code();
            if (low < 0xdc00 || low > 0xdfff)
              return false;
          } else if (n >= 0xdc00 && n <= 0xdfff)
            return false;
        } else if (escaped != '"' && escaped != '\\' && escaped != '/' &&
                   escaped != 'b' && escaped != 'f' && escaped != 'n' &&
                   escaped != 'r' && escaped != 't')
          return false;
      }
    }
    return false;
  }
  bool digit() { return p < s.size() && s[p] >= '0' && s[p] <= '9'; }
  bool value() {
    space();
    if (++depth > 32 || p == s.size())
      return false;
    bool ok = false;
    if (s[p] == '"')
      ok = string();
    else if (take('{')) {
      space();
      if (take('}'))
        ok = true;
      else
        for (;;) {
          if (!string())
            break;
          space();
          if (!take(':') || !value())
            break;
          space();
          if (take('}')) {
            ok = true;
            break;
          }
          if (!take(','))
            break;
          space();
        }
    } else if (take('[')) {
      space();
      if (take(']'))
        ok = true;
      else
        for (;;) {
          if (!value())
            break;
          space();
          if (take(']')) {
            ok = true;
            break;
          }
          if (!take(','))
            break;
        }
    } else if (s.compare(p, 4, "true") == 0) {
      p += 4;
      ok = true;
    } else if (s.compare(p, 5, "false") == 0) {
      p += 5;
      ok = true;
    } else if (s.compare(p, 4, "null") == 0) {
      p += 4;
      ok = true;
    } else {
      take('-');
      size_t start = p;
      if (take('0')) {
      } else if (p < s.size() && s[p] >= '1' && s[p] <= '9') {
        while (digit())
          p++;
      }
      if (p > start) {
        ok = true;
        if (take('.')) {
          if (!digit())
            ok = false;
          while (digit())
            p++;
        }
        if (take('e') || take('E')) {
          if (!take('+'))
            take('-');
          if (!digit())
            ok = false;
          while (digit())
            p++;
        }
      }
    }
    depth--;
    return ok;
  }
  bool valid() {
    bool ok = value();
    space();
    return ok && p == s.size();
  }
};
Fd::~Fd() {
  if (value >= 0)
    close(value);
}
J parse(const std::string &s) {
  need(s.size() <= 128 * 1024 * 1024 && s.size() <= INT32_MAX, STATE);
  json_tokener *t = json_tokener_new_ex(32);
  need(t != nullptr, STATE);
  /* Validate JSON grammar and UTF8 independently: json-c STRICT rejects valid
   * non-ASCII strings on some musl builds in the C locale. */
  if (!utf8(s) || !StrictJson{s}.valid()) {
    json_tokener_free(t);
    throw Failure(STATE);
  }
  json_tokener_set_flags(t, 0);
  auto *p = json_tokener_parse_ex(t, s.data(), static_cast<int>(s.size()));
  bool ok = json_tokener_get_error(t) == json_tokener_success;
  size_t end = json_tokener_get_parse_end(t);
  json_tokener_free(t);
  while (end < s.size() &&
         (s[end] == ' ' || s[end] == '\t' || s[end] == '\r' || s[end] == '\n'))
    end++;
  if (!ok || end != s.size() || !p) {
    if (p)
      json_object_put(p);
    throw Failure(STATE);
  }
  return own(p);
}
std::string dump(const J &j) {
  return json_object_to_json_string_ext(j.get(), JSON_C_TO_STRING_PLAIN);
}
J copy(const J &j) { return parse(dump(j)); }
J get(const J &j, const char *key, bool required) {
  json_object *p = nullptr;
  need(json_object_is_type(j.get(), json_type_object), STATE);
  if (!json_object_object_get_ex(j.get(), key, &p)) {
    need(!required, STATE);
    return {};
  }
  return own(json_object_get(p));
}
std::string str(const J &j) {
  need(j && json_object_is_type(j.get(), json_type_string), CONFIG);
  std::string s(json_object_get_string(j.get()),
                json_object_get_string_len(j.get()));
  need(s.find('\0') == std::string::npos, CONFIG);
  return s;
}
std::string text(const J &j, const char *key, const std::string &fallback) {
  auto p = get(j, key, false);
  return p ? str(p) : fallback;
}
uint64_t number(const J &j, const char *key, uint64_t fallback) {
  auto p = get(j, key, false);
  if (!p)
    return fallback;
  need(json_object_is_type(p.get(), json_type_int) &&
           json_object_get_int64(p.get()) >= 0,
       STATE);
  return json_object_get_uint64(p.get());
}
bool flag(const J &j, const char *key, bool fallback) {
  auto p = get(j, key, false);
  if (!p)
    return fallback;
  need(json_object_is_type(p.get(), json_type_boolean), CONFIG);
  return json_object_get_boolean(p.get());
}
void put(const J &j, const char *k, const std::string &s) {
  need(s.size() <= INT32_MAX, STATE);
  json_object_object_add(
      j.get(), k,
      json_object_new_string_len(s.data(), static_cast<int>(s.size())));
}
void put(const J &j, const char *k, uint64_t n) {
  json_object_object_add(j.get(), k, json_object_new_uint64(n));
}
void put(const J &j, const char *k, const J &v) {
  json_object_object_add(j.get(), k, json_object_get(v.get()));
}
static std::string hex(const unsigned char *p, size_t n) {
  const char *digits = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = digits[p[i] >> 4];
    s[2 * i + 1] = digits[p[i] & 15];
  }
  return s;
}
std::string sha(const std::string &s) {
  unsigned char digest[32];
  unsigned n = 0;
  need(EVP_Digest(s.data(), s.size(), digest, &n, EVP_sha256(), nullptr) == 1 &&
           n == 32,
       STATE);
  return hex(digest, 32);
}
std::string random_id() {
  unsigned char raw[16];
  need(RAND_bytes(raw, 16) == 1, STATE);
  return hex(raw, 16);
}
std::string base64(const std::string &raw) {
  std::string out(4 * ((raw.size() + 2) / 3) + 1, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
                          reinterpret_cast<const unsigned char *>(raw.data()),
                          static_cast<int>(raw.size()));
  need(n >= 0, STATE);
  out.resize(n);
  return out;
}
bool utf8(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    unsigned c = static_cast<unsigned char>(s[i++]), n = 0, value = 0,
             minimum = 0;
    if (c < 128)
      continue;
    if (c >= 194 && c <= 223) {
      n = 1;
      value = c & 31;
      minimum = 128;
    } else if (c >= 224 && c <= 239) {
      n = 2;
      value = c & 15;
      minimum = 2048;
    } else if (c >= 240 && c <= 244) {
      n = 3;
      value = c & 7;
      minimum = 65536;
    } else
      return false;
    if (s.size() - i < n)
      return false;
    while (n--) {
      unsigned d = static_cast<unsigned char>(s[i++]);
      if ((d & 192) != 128)
        return false;
      value = (value << 6) | (d & 63);
    }
    if (value < minimum || value > 0x10ffff ||
        (value >= 0xd800 && value <= 0xdfff))
      return false;
  }
  return true;
}
std::string now() {
  auto clock = std::chrono::system_clock::now();
  auto seconds = std::chrono::system_clock::to_time_t(clock);
  struct tm t{};
  gmtime_r(&seconds, &t);
  char s[64];
  strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &t);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                clock.time_since_epoch())
                .count() %
            1000;
  char suffix[8];
  snprintf(suffix, sizeof(suffix), ".%03d", static_cast<int>(ms));
  return std::string(s) + suffix;
}
uint64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
void absolute(const std::string &path) {
  need(path.size() > 1 && path.front() == '/' && path.back() != '/' &&
           path.size() <= 4096,
       CONFIG);
  size_t start = 1;
  while (start < path.size()) {
    auto end = path.find('/', start);
    auto part = path.substr(start, end - start);
    need(!part.empty() && part != "." && part != "..", CONFIG);
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
}
int safe_open(const std::string &path, int flags, unsigned mode) {
  absolute(path);
  Fd dir(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  need(dir.value >= 0, IO);
  size_t start = 1;
  for (;;) {
    auto end = path.find('/', start);
    auto part = path.substr(start, end - start);
    int fd = openat(dir.value, part.c_str(),
                    end == std::string::npos
                        ? flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                        : O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                    mode);
    if (fd < 0)
      return -1;
    if (end == std::string::npos)
      return fd;
    close(dir.value);
    dir.value = fd;
    start = end + 1;
  }
}
std::string read_file(const std::string &path, size_t limit, bool secret) {
  Fd fd(safe_open(path, O_RDONLY));
  need(fd.value >= 0, IO);
  struct stat st{};
  need(!fstat(fd.value, &st) && S_ISREG(st.st_mode) && st.st_size >= 0 &&
           static_cast<uint64_t>(st.st_size) <= limit,
       IO);
  if (secret)
    need((st.st_mode & 077) == 0 && (st.st_uid == geteuid() || geteuid() == 0),
         CONFIG);
  std::string out;
  char buffer[8192];
  for (;;) {
    ssize_t n = read(fd.value, buffer, sizeof(buffer));
    if (n < 0 && errno == EINTR)
      continue;
    need(n >= 0, IO);
    if (!n)
      break;
    need(out.size() + static_cast<size_t>(n) <= limit, IO);
    out.append(buffer, n);
  }
  return out;
}
static bool identifier(const std::string &s, bool index = false) {
  if (s.empty() || s.size() > 128)
    return false;
  for (char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
          (index && (c == '-' || c == '.'))))
      return false;
  return !index || (s.front() != '-' && s.front() != '_' && s.front() != '.' &&
                    s != "." && s != "..");
}
static bool label(const std::string &s) {
  if (s.empty() || s.size() > 128)
    return false;
  for (unsigned char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
      return false;
  return true;
}
static void keys(const J &j, std::initializer_list<const char *> allowed) {
  need(json_object_is_type(j.get(), json_type_object), CONFIG);
  json_object_object_foreach(j.get(), name, value) {
    (void)value;
    bool found = false;
    for (auto key : allowed)
      if (!strcmp(name, key))
        found = true;
    need(found, CONFIG);
  }
}
Config config_read(const std::string &path) {
  static std::once_flag initialize;
  std::call_once(initialize, [] {
    need(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, TRANSPORT);
  });
  Config c;
  auto j = parse(read_file(path, 1024 * 1024));
  keys(j, {"node", "state_dir", "sources", "sinks", "batch_records",
           "batch_bytes", "line_bytes", "max_files", "timeout_ms", "connect_ms",
           "retry_ms", "telemetry"});
  c.node = text(j, "node");
  need(label(c.node), CONFIG);
  c.state = text(j, "state_dir");
  absolute(c.state);
  c.batch_records = number(j, "batch_records", 512);
  c.batch_bytes = number(j, "batch_bytes", 4 * 1024 * 1024);
  c.line_bytes = number(j, "line_bytes", 65536);
  c.max_files = number(j, "max_files", 4096);
  uint64_t timeout = number(j, "timeout_ms", 10000),
           connect = number(j, "connect_ms", 2000),
           retry = number(j, "retry_ms", 1000);
  need(c.batch_records >= 1 && c.batch_records <= 4096 &&
           c.line_bytes >= 1024 && c.line_bytes <= 4 * 1024 * 1024 &&
           c.batch_bytes >= c.line_bytes * 4 + 8192 &&
           c.batch_bytes <= 32 * 1024 * 1024 && c.max_files >= 1 &&
           c.max_files <= 16384 && timeout >= 100 && timeout <= 60000 &&
           connect >= 50 && connect <= timeout && retry >= 50 && retry <= 60000,
       CONFIG);
  c.timeout_ms = timeout;
  c.connect_ms = connect;
  c.retry_ms = retry;
  auto sources = get(j, "sources"), sinks = get(j, "sinks");
  need(json_object_is_type(sources.get(), json_type_array) &&
           json_object_array_length(sources.get()) >= 1 &&
           json_object_array_length(sources.get()) <= 63 &&
           json_object_is_type(sinks.get(), json_type_array) &&
           json_object_array_length(sinks.get()) >= 1 &&
           json_object_array_length(sinks.get()) <= 8,
       CONFIG);
  std::set<std::string> ids;
  for (size_t i = 0; i < json_object_array_length(sources.get()); i++) {
    auto s = own(json_object_get(json_object_array_get_idx(sources.get(), i)));
    keys(s, {"id", "paths", "start", "format", "kind"});
    Source source;
    source.id = text(s, "id");
    need(label(source.id) && ids.insert(source.id).second, CONFIG);
    need(source.id != "telemetry", CONFIG);
    source.kind = text(s, "kind", "log");
    need(source.kind == "log" || source.kind == "access" ||
             source.kind == "ban",
         CONFIG);
    source.start = text(s, "start", "full");
    source.format = text(s, "format", "auto");
    need(source.start == "full" || source.start == "tail", CONFIG);
    need(source.format == "auto" || source.format == "json" ||
             source.format == "text",
         CONFIG);
    auto paths = get(s, "paths");
    need(json_object_is_type(paths.get(), json_type_array) &&
             json_object_array_length(paths.get()) >= 1 &&
             json_object_array_length(paths.get()) <= 32,
         CONFIG);
    for (size_t n = 0; n < json_object_array_length(paths.get()); n++) {
      auto p =
          str(own(json_object_get(json_object_array_get_idx(paths.get(), n))));
      absolute(p);
      auto dir = p.substr(0, p.rfind('/'));
      need(dir.find_first_of("*?[") == std::string::npos, CONFIG);
      need(p.compare(0, c.state.size() + 1, c.state + "/") != 0, CONFIG);
      source.paths.push_back(p);
    }
    c.sources.push_back(source);
  }
  ids.clear();
  for (size_t i = 0; i < json_object_array_length(sinks.get()); i++) {
    auto s = own(json_object_get(json_object_array_get_idx(sinks.get(), i)));
    keys(s, {"id", "type", "endpoint", "index", "database", "table",
             "authorization_file", "username_file", "password_file", "ca_file",
             "allow_http"});
    Sink sink;
    sink.id = text(s, "id");
    need(label(sink.id) && ids.insert(sink.id).second, CONFIG);
    sink.type = text(s, "type");
    need(sink.type == "elasticsearch" || sink.type == "clickhouse", CONFIG);
    sink.endpoint = text(s, "endpoint");
    CURLU *u = curl_url();
    need(u != nullptr, CONFIG);
    CURLUcode parsed = curl_url_set(u, CURLUPART_URL, sink.endpoint.c_str(), 0);
    bool valid = parsed == CURLUE_OK;
    char *scheme = nullptr, *user = nullptr, *password = nullptr,
         *query = nullptr, *fragment = nullptr;
    curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(u, CURLUPART_USER, &user, 0);
    curl_url_get(u, CURLUPART_PASSWORD, &password, 0);
    curl_url_get(u, CURLUPART_QUERY, &query, 0);
    curl_url_get(u, CURLUPART_FRAGMENT, &fragment, 0);
    valid = valid && scheme && !user && !password && !query && !fragment &&
            (!strcmp(scheme, "https") ||
             (!strcmp(scheme, "http") && flag(s, "allow_http")));
    curl_free(scheme);
    curl_free(user);
    curl_free(password);
    curl_free(query);
    curl_free(fragment);
    curl_url_cleanup(u);
    need(valid, CONFIG);
    while (!sink.endpoint.empty() && sink.endpoint.back() == '/')
      sink.endpoint.pop_back();
    sink.index = text(s, "index", "scdn-logs");
    sink.database = text(s, "database", "default");
    sink.table = text(s, "table", "scdn_logs");
    need(identifier(sink.index, true) && identifier(sink.database) &&
             identifier(sink.table),
         CONFIG);
    sink.authorization_file = text(s, "authorization_file");
    sink.username_file = text(s, "username_file");
    sink.password_file = text(s, "password_file");
    sink.ca_file = text(s, "ca_file");
    need(sink.username_file.empty() == sink.password_file.empty(), CONFIG);
    need(sink.authorization_file.empty() || sink.username_file.empty(), CONFIG);
    for (auto &file : {sink.authorization_file, sink.username_file,
                       sink.password_file, sink.ca_file})
      if (!file.empty())
        absolute(file);
    c.sinks.push_back(sink);
  }
  auto telemetry = get(j, "telemetry", false);
  if (telemetry) {
    keys(telemetry,
         {"enabled", "interval_ms", "spool_bytes", "rotate_bytes", "proc_root",
          "pid_file", "cache_path", "sites_file", "packet_file", "ban_socket",
          "ban_counter_map", "endpoints"});
    auto &t = c.telemetry;
    t.enabled = flag(telemetry, "enabled", true);
    t.interval_ms = number(telemetry, "interval_ms", 1000);
    t.spool_bytes = number(telemetry, "spool_bytes", 256 * 1024 * 1024);
    t.rotate_bytes = number(telemetry, "rotate_bytes", 8 * 1024 * 1024);
    need(t.interval_ms >= 100 && t.interval_ms <= 60000 &&
             t.rotate_bytes >= 65536 && t.rotate_bytes <= 64 * 1024 * 1024 &&
             t.spool_bytes >= t.rotate_bytes * 2 &&
             t.spool_bytes <= 4ULL * 1024 * 1024 * 1024,
         CONFIG);
    t.proc_root = text(telemetry, "proc_root", "/proc");
    t.pid_file = text(telemetry, "pid_file");
    t.cache_path = text(telemetry, "cache_path");
    t.sites_file = text(telemetry, "sites_file");
    t.packet_file = text(telemetry, "packet_file");
    t.ban_socket = text(telemetry, "ban_socket");
    t.ban_counter_map = text(telemetry, "ban_counter_map");
    for (auto &p : {t.proc_root, t.pid_file, t.cache_path, t.sites_file,
                    t.packet_file, t.ban_socket, t.ban_counter_map})
      if (!p.empty())
        absolute(p);
    auto endpoints = get(telemetry, "endpoints", false);
    std::set<std::string> names;
    if (endpoints) {
      need(json_object_is_type(endpoints.get(), json_type_array) &&
               json_object_array_length(endpoints.get()) <= 16,
           CONFIG);
      for (size_t i = 0; i < json_object_array_length(endpoints.get()); i++) {
        auto e =
            own(json_object_get(json_object_array_get_idx(endpoints.get(), i)));
        keys(e,
             {"id", "url", "socket", "path", "format", "authorization_file"});
        StatusSource status;
        status.id = text(e, "id");
        need(label(status.id) && names.insert(status.id).second, CONFIG);
        status.socket = text(e, "socket");
        status.path = text(e, "path", "/");
        status.url = text(e, "url");
        status.authorization_file = text(e, "authorization_file");
        status.format = text(e, "format", "json");
        need(status.format == "json" || status.format == "prometheus", CONFIG);
        if (!status.socket.empty()) {
          absolute(status.socket);
          need(status.url.empty() && !status.path.empty() &&
                   status.path[0] == '/' &&
                   status.path.find_first_of("\r\n") == std::string::npos,
               CONFIG);
        } else {
          need(status.url.compare(0, 8, "https://") == 0 ||
                   status.url.compare(0, 17, "http://127.0.0.1:") == 0 ||
                   status.url.compare(0, 13, "http://[::1]:") == 0,
               CONFIG);
          need(status.url.find('@') == std::string::npos &&
                   status.url.find('?') == std::string::npos &&
                   status.url.find('#') == std::string::npos,
               CONFIG);
        }
        if (!status.authorization_file.empty())
          absolute(status.authorization_file);
        t.endpoints.push_back(status);
      }
    }
  }
  /* Disabling future sampling must still drain already durable segments. */
  Source internal;
  internal.id = "telemetry";
  internal.kind = "metrics";
  internal.start = "full";
  internal.format = "json";
  internal.paths = {c.state + "/telemetry-*.jsonl"};
  c.sources.push_back(internal);
  auto binding = obj();
  put(binding, "node", c.node);
  put(binding, "sources", sources);
  put(binding, "sinks", sinks);
  c.binding = sha(dump(binding));
  return c;
}
} // namespace logs
