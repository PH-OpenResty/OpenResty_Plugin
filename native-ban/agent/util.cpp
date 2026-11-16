#include "ban.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <curl/curl.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
namespace ban {
void require(bool c, const std::string &e) {
  if (!c)
    throw std::runtime_error(e);
}
J object() { return own(json_object_new_object()); }
J parse(const std::string &s) {
  require(s.size() <= BAN_MAX_FRAME, "json_size");
  // json-c otherwise accepts repeated keys by keeping the last value.
  // Detect decoded key duplicates in each bounded object before parsing.
  std::vector<std::set<std::string>> objects;
  std::vector<bool> is_object;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '{' || s[i] == '[') {
      require(objects.size() < 32, "json_depth");
      objects.emplace_back();
      is_object.push_back(s[i] == '{');
    } else if (s[i] == '}' || s[i] == ']') {
      require(!objects.empty(), "json_nesting");
      objects.pop_back();
      is_object.pop_back();
    } else if (s[i] == '"') {
      size_t start = i++;
      while (i < s.size() && s[i] != '"') {
        if (s[i] == '\\')
          i++;
        i++;
      }
      require(i < s.size(), "json_string");
      size_t next = i + 1;
      while (next < s.size() && isspace((unsigned char)s[next]))
        next++;
      if (next < s.size() && s[next] == ':') {
        require(!objects.empty() && is_object.back(), "json_key");
        auto raw = s.substr(start, i - start + 1);
        auto key = own(json_tokener_parse(raw.c_str()));
        require(key && json_object_is_type(key.get(), json_type_string),
                "json_key");
        std::string decoded(json_object_get_string(key.get()),
                            json_object_get_string_len(key.get()));
        require(decoded.find('\0') == std::string::npos &&
                    objects.back().insert(decoded).second,
                "duplicate_json_key");
      }
    }
  }
  auto *t = json_tokener_new_ex(32);
  require(t, "allocation");
  json_tokener_set_flags(t, JSON_TOKENER_STRICT);
  json_object *p = json_tokener_parse_ex(t, s.data(), (int)s.size());
  auto error = json_tokener_get_error(t);
  size_t end = json_tokener_get_parse_end(t);
  json_tokener_free(t);
  auto result = own(p);
  require(error == json_tokener_success && p &&
              json_object_is_type(p, json_type_object),
          "invalid_json");
  while (end < s.size() && isspace((unsigned char)s[end]))
    end++;
  require(end == s.size(), "trailing_json");
  return result;
}
std::string dump(const J &j) {
  return json_object_to_json_string_ext(j.get(), JSON_C_TO_STRING_PLAIN);
}
J get(const J &j, const char *k) {
  json_object *p = nullptr;
  require(json_object_object_get_ex(j.get(), k, &p),
          std::string("missing_") + k);
  return own(json_object_get(p));
}
std::string str(const J &j, const char *k) {
  auto v = get(j, k);
  require(json_object_is_type(v.get(), json_type_string),
          std::string("string_") + k);
  std::string s(json_object_get_string(v.get()),
                json_object_get_string_len(v.get()));
  require(s.find('\0') == std::string::npos, "nul_string");
  return s;
}
int64_t num(const J &j, const char *k) {
  auto v = get(j, k);
  require(json_object_is_type(v.get(), json_type_int),
          std::string("integer_") + k);
  return json_object_get_int64(v.get());
}
void set(J &j, const char *k, const std::string &v) {
  json_object_object_add(j.get(), k,
                         json_object_new_string_len(v.data(), (int)v.size()));
}
void set(J &j, const char *k, int64_t v) {
  json_object_object_add(j.get(), k, json_object_new_int64(v));
}
void set(J &j, const char *k, const J &v) {
  json_object_object_add(j.get(), k, json_object_get(v.get()));
}
void keys(const J &j, const std::string &allowed) {
  require(json_object_is_type(j.get(), json_type_object), "object_required");
  json_object_object_foreach(j.get(), key, value) {
    (void)value;
    require((" " + allowed + " ").find(" " + std::string(key) + " ") !=
                std::string::npos,
            std::string("unknown_") + key);
  }
}
std::string hex(const void *p, size_t n) {
  const auto *b = (const unsigned char *)p;
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = "0123456789abcdef"[b[i] >> 4];
    s[2 * i + 1] = "0123456789abcdef"[b[i] & 15];
  }
  return s;
}
std::string random_id() {
  uint8_t b[16];
  require(RAND_bytes(b, 16) == 1, "random_failed");
  return hex(b, 16);
}
std::string sha(const std::string &s) {
  unsigned char out[32];
  unsigned n;
  require(EVP_Digest(s.data(), s.size(), out, &n, EVP_sha256(), nullptr) == 1 &&
              n == 32,
          "digest_failed");
  return hex(out, 32);
}
int safe_open(const std::string &path, int flags, mode_t mode) {
  require(path.size() > 1 && path[0] == '/' && path.back() != '/',
          "absolute_path_required");
  int fd = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  require(fd >= 0, "open_root");
  size_t start = 1;
  while (start < path.size()) {
    auto end = path.find('/', start);
    auto part =
        path.substr(start, end == std::string::npos ? end : end - start);
    if (part.empty() || part == "." || part == "..") {
      close(fd);
      throw std::runtime_error("unsafe_path");
    }
    int next = openat(fd, part.c_str(),
                      end == std::string::npos
                          ? (flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                          : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                      mode);
    close(fd);
    fd = next;
    if (fd < 0)
      return -1;
    if (end == std::string::npos)
      return fd;
    start = end + 1;
  }
  close(fd);
  return -1;
}
std::string read_file(const std::string &path, size_t max, bool secret) {
  int fd = safe_open(path, O_RDONLY);
  require(fd >= 0, "file_unavailable");
  struct stat st;
  std::string s;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uint64_t)st.st_size > max || (secret && (st.st_mode & 077))) {
    close(fd);
    throw std::runtime_error("unsafe_file");
  }
  s.resize((size_t)st.st_size);
  if (path.rfind("/proc/", 0) == 0) {
    s.resize(max + 1);
    ssize_t n = read(fd, s.data(), s.size());
    close(fd);
    require(n >= 0 && (size_t)n <= max, "proc_read");
    s.resize((size_t)n);
    return s;
  }
  size_t i = 0;
  while (i < s.size()) {
    ssize_t n = read(fd, &s[i], s.size() - i);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close(fd);
      throw std::runtime_error("short_read");
    }
    i += (size_t)n;
  }
  close(fd);
  return s;
}
void atomic_file(const std::string &path, const std::string &bytes) {
  auto slash = path.rfind('/');
  int dir = safe_open(path.substr(0, slash), O_RDONLY | O_DIRECTORY);
  require(dir >= 0, "directory_unavailable");
  auto name = path.substr(slash + 1), tmp = ".tmp-" + random_id();
  int fd = openat(dir, tmp.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    close(dir);
    throw std::runtime_error("file_create");
  }
  bool ok = true;
  size_t i = 0;
  while (i < bytes.size()) {
    ssize_t n = write(fd, bytes.data() + i, bytes.size() - i);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      ok = false;
      break;
    }
    i += (size_t)n;
  }
  if (ok)
    ok = !fsync(fd) && !renameat(dir, tmp.c_str(), dir, name.c_str()) &&
         !fsync(dir);
  close(fd);
  unlinkat(dir, tmp.c_str(), 0);
  close(dir);
  require(ok, "durable_write");
}
int64_t utc() {
  struct timespec t;
  require(!clock_gettime(CLOCK_REALTIME, &t), "clock_failed");
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
std::string boot_id() {
  auto s = read_file("/proc/sys/kernel/random/boot_id", 64);
  while (!s.empty() && isspace((unsigned char)s.back()))
    s.pop_back();
  return s;
}
ban_address ip_parse(const std::string &s) {
  ban_address a;
  require(ban_address_parse(s.c_str(), &a), "invalid_ip");
  return a;
}
std::string ip_text(const ban_address &a) {
  char s[INET6_ADDRSTRLEN];
  require(inet_ntop(a.family == 4 ? AF_INET : AF_INET6,
                    a.address + (a.family == 4 ? 12 : 0), s, sizeof(s)),
          "invalid_address");
  return s;
}
bool id_valid(const std::string &s) {
  if (s.empty() || s.size() > 95)
    return false;
  for (size_t i = 0; i < s.size(); i++)
    if (!isalnum((unsigned char)s[i]) &&
        (i == 0 || (s[i] != '_' && s[i] != '-')))
      return false;
  return true;
}
bool reason_valid(const std::string &s) {
  if (s.empty() || s.size() > 63)
    return false;
  for (auto c : s)
    if (!isalnum((unsigned char)c) && c != '_' && c != '-' && c != ':' &&
        c != '.')
      return false;
  return true;
}
static std::string b64(const std::string &s) {
  std::string out(4 * ((s.size() + 2) / 3), '\0');
  EVP_EncodeBlock((unsigned char *)out.data(), (const unsigned char *)s.data(),
                  (int)s.size());
  return out;
}
static std::string unb64(const std::string &s) {
  require(!s.empty() && s.size() % 4 == 0 && s.size() < BAN_MAX_FRAME,
          "base64_size");
  std::string out(s.size() / 4 * 3, '\0');
  int n = EVP_DecodeBlock((unsigned char *)out.data(),
                          (const unsigned char *)s.data(), (int)s.size());
  require(n >= 0, "base64_invalid");
  if (s.back() == '=')
    n--;
  if (s[s.size() - 2] == '=')
    n--;
  out.resize(n);
  return out;
}
static EVP_PKEY *key_read(const std::string &path, bool priv) {
  auto bytes = read_file(path, 65536, priv);
  BIO *b = BIO_new_mem_buf(bytes.data(), (int)bytes.size());
  require(b, "key_buffer");
  auto *k = priv ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, (void *)"")
                 : PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
  BIO_free(b);
  OPENSSL_cleanse(bytes.data(), bytes.size());
  require(k && EVP_PKEY_base_id(k) == EVP_PKEY_ED25519, "ed25519_key_required");
  return k;
}
std::string sign_snapshot(const Config &c, const std::string &payload) {
  EVP_PKEY *k = key_read(c.sign, true);
  EVP_MD_CTX *m = EVP_MD_CTX_new();
  unsigned char sig[64];
  size_t n = 64;
  bool ok = m && EVP_DigestSignInit(m, nullptr, nullptr, nullptr, k) == 1 &&
            EVP_DigestSign(m, sig, &n, (const unsigned char *)payload.data(),
                           payload.size()) == 1;
  EVP_MD_CTX_free(m);
  EVP_PKEY_free(k);
  require(ok && n == 64, "signature_failed");
  auto j = object();
  set(j, "payload", b64(payload));
  set(j, "signature", b64(std::string((char *)sig, 64)));
  return dump(j);
}
std::string verify_snapshot(const Config &c, const std::string &envelope) {
  auto j = parse(envelope);
  keys(j, "payload signature");
  auto payload = unb64(str(j, "payload")), sig = unb64(str(j, "signature"));
  require(sig.size() == 64, "signature_size");
  EVP_PKEY *k = key_read(c.verify, false);
  EVP_MD_CTX *m = EVP_MD_CTX_new();
  bool ok = m && EVP_DigestVerifyInit(m, nullptr, nullptr, nullptr, k) == 1 &&
            EVP_DigestVerify(m, (const unsigned char *)sig.data(), sig.size(),
                             (const unsigned char *)payload.data(),
                             payload.size()) == 1;
  EVP_MD_CTX_free(m);
  EVP_PKEY_free(k);
  require(ok, "signature_invalid");
  return payload;
}
static size_t receive(char *p, size_t n, size_t m, void *d) {
  auto *s = (std::string *)d;
  size_t size = n * m;
  if (size > BAN_MAX_FRAME - s->size())
    return 0;
  s->append(p, size);
  return size;
}
std::pair<int, std::string> http(const Config &c, const std::string &path,
                                 const std::string &body) {
  CURL *h = curl_easy_init();
  require(h, "http_allocate");
  std::string response, url = c.master_url + path;
  curl_easy_setopt(h, CURLOPT_URL, url.c_str());
  curl_easy_setopt(h, CURLOPT_PROXY, "");
  curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
  curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, 3000L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(h, CURLOPT_CAINFO, c.ca.c_str());
  curl_easy_setopt(h, CURLOPT_SSLCERT, c.cert.c_str());
  curl_easy_setopt(h, CURLOPT_SSLKEY, c.key.c_str());
  if (!body.empty()) {
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)body.size());
  }
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, &response);
  auto code = curl_easy_perform(h);
  long status = 0;
  curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
  curl_easy_cleanup(h);
  return {code == CURLE_OK ? (int)status : 0, response};
}
} // namespace ban
