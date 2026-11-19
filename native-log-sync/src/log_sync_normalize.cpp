#include "log_sync.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <sys/stat.h>

namespace logs {
static std::string scalar(const J &j, const char *key,
                          const std::string &fallback = "") {
  json_object *value = nullptr;
  if (!json_object_object_get_ex(j.get(), key, &value) || !value)
    return fallback;
  if (json_object_is_type(value, json_type_string))
    return json_object_get_string(value);
  return json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
}
static double numeric(const J &j, const char *key) {
  json_object *v = nullptr;
  if (!json_object_object_get_ex(j.get(), key, &v) || !v)
    return 0;
  double n = json_object_get_double(v);
  return std::isfinite(n) && n > 0 ? n : 0;
}
bool internal_ip(const std::string &ip, unsigned &family) {
  unsigned char raw[16];
  if (inet_pton(AF_INET, ip.c_str(), raw) == 1) {
    family = 4;
    if (raw[0] == 192 && raw[1] == 0 && raw[2] == 0 &&
        (raw[3] == 9 || raw[3] == 10))
      return false;
    return raw[0] == 0 || raw[0] == 10 || raw[0] == 127 || raw[0] >= 224 ||
           (raw[0] == 169 && raw[1] == 254) ||
           (raw[0] == 172 && raw[1] >= 16 && raw[1] <= 31) ||
           (raw[0] == 192 && raw[1] == 168) ||
           (raw[0] == 100 && raw[1] >= 64 && raw[1] <= 127) ||
           (raw[0] == 192 && raw[1] == 0 && (raw[2] == 0 || raw[2] == 2)) ||
           (raw[0] == 198 && (raw[1] == 18 || raw[1] == 19 ||
                              (raw[1] == 51 && raw[2] == 100))) ||
           (raw[0] == 203 && raw[1] == 0 && raw[2] == 113);
  }
  if (inet_pton(AF_INET6, ip.c_str(), raw) == 1) {
    family = 6;
    bool mapped = true;
    for (unsigned i = 0; i < 10; i++)
      mapped &= raw[i] == 0;
    if (mapped && raw[10] == 255 && raw[11] == 255) {
      char v4[INET_ADDRSTRLEN];
      unsigned ignored = 0;
      if (inet_ntop(AF_INET, raw + 12, v4, sizeof(v4)))
        return internal_ip(v4, ignored);
    }
    unsigned any = 0;
    for (unsigned i = 0; i < 15; i++)
      any |= raw[i];
    return (!any && (raw[15] == 0 || raw[15] == 1)) ||
           (raw[0] & 0xfe) == 0xfc ||
           (raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) || raw[0] == 0xff ||
           (raw[0] == 0x20 && raw[1] == 1 && raw[2] == 0x0d && raw[3] == 0xb8);
  }
  family = 0;
  return true;
}
static std::string operator_name(std::string org) {
  std::string upper = org;
  std::transform(upper.begin(), upper.end(), upper.begin(),
                 [](unsigned char c) { return std::toupper(c); });
  const std::pair<const char *, const char *> patterns[] = {
      {"UNICOM", "中国联通"},         {"CHINA169", "中国联通"},
      {"CNCGROUP", "中国联通"},       {"CHINANET", "中国电信"},
      {"CHINA TELECOM", "中国电信"},  {"CHINATELECOM", "中国电信"},
      {"CHINA MOBILE", "中国移动"},   {"CMNET", "中国移动"},
      {"CMCC", "中国移动"},           {"CERNET", "中国教育科研网"},
      {"CHINA BROADNET", "中国广电"}, {"CHINABROADNET", "中国广电"},
      {"CLOUDFLARE", "Cloudflare"},   {"AMAZON", "Amazon AWS"},
      {"AWS", "Amazon AWS"},          {"GOOGLE", "Google"},
      {"ORACLE", "Oracle"},           {"MICROSOFT", "Microsoft"},
      {"TENCENT", "腾讯云"},          {"ALIBABA", "阿里云"},
      {"ALIYUN", "阿里云"},           {"HUAWEI", "华为云"},
      {"BYTEDANCE", "火山引擎"},      {"VOLCENGINE", "火山引擎"}};
  for (auto &p : patterns)
    if (upper.find(p.first) != std::string::npos)
      return p.second;
  return org.empty() ? "unknown" : org;
}
J normalize(const Config &c, const Source &source, const J &fields,
            const std::string &fallback) {
  if (source.kind != "access" && source.kind != "ban")
    return {};
  if (source.kind == "access" &&
      (scalar(fields, "time", scalar(fields, "timestamp")).empty() ||
       numeric(fields, "status") < 100 || numeric(fields, "status") > 599))
    return {};
  if (source.kind == "ban" &&
      (numeric(fields, "time_ms") == 0 || scalar(fields, "action").empty() ||
       scalar(fields, "ip").empty()))
    return {};
  auto row = obj();
  put(row, "node", c.node);
  put(row, "event_id", fallback);
  std::string ip = scalar(fields, "client_ip",
                          scalar(fields, "remote_addr", scalar(fields, "ip")));
  unsigned family = 0;
  bool priv = internal_ip(ip, family);
  put(row, "ip", ip);
  put(row, "internal", priv ? uint64_t(1) : uint64_t(0));
  if (source.kind == "ban") {
    for (auto key :
         {"node_id", "seq", "time_ms", "ban_id", "action", "reason", "origin"})
      put(row, key, scalar(fields, key));
    if (!scalar(fields, "node_id").empty() &&
        !scalar(fields, "time_ms").empty() &&
        !scalar(fields, "ban_id").empty() && !scalar(fields, "action").empty())
      put(row, "event_id",
          sha(c.node + "|ban|" + scalar(fields, "node_id") + "|" +
              scalar(fields, "seq") + "|" + scalar(fields, "time_ms") + "|" +
              scalar(fields, "ban_id") + "|" + scalar(fields, "action")));
    auto scope = scalar(fields, "scope", "*");
    put(row, "scope", scope == "cdn-unregistered" ? "__unregistered__" : scope);
    put(row, "source", scalar(fields, "source"));
    put(row, "layer", uint64_t(numeric(fields, "layer")));
    json_object *applied = nullptr;
    bool yes = json_object_object_get_ex(fields.get(), "applied", &applied) &&
               json_object_get_boolean(applied);
    put(row, "applied", yes ? uint64_t(1) : uint64_t(0));
    return row;
  }
  auto event_time = scalar(fields, "time", scalar(fields, "timestamp"));
  if (!event_time.empty()) {
    char *end = nullptr;
    double value = std::strtod(event_time.c_str(), &end);
    if (end == event_time.c_str() + event_time.size() && std::isfinite(value) &&
        value >= 0) {
      if (value > 100000000000.0)
        value /= 1000;
      if (value < 100000000000.0) {
        time_t seconds = static_cast<time_t>(value);
        struct tm utc{};
        gmtime_r(&seconds, &utc);
        char stamp[64];
        if (strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &utc)) {
          char suffix[8];
          snprintf(suffix, sizeof(suffix), ".%03u",
                   unsigned((value - std::floor(value)) * 1000));
          event_time = std::string(stamp) + suffix;
        }
      }
    }
  }
  put(row, "time", event_time);
  put(row, "ip_family", uint64_t(family));
  auto request = scalar(fields, "request_id");
  if (request.size() == 32 &&
      request.find_first_not_of("abcdefABCDEF0123456789") == std::string::npos)
    put(row, "event_id", sha(c.node + "|r:" + request));
  put(row, "request_id", request);
  auto host = scalar(fields, "host");
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char ch) { return std::tolower(ch); });
  put(row, "host", host);
  put(row, "site",
      scalar(fields, "site_id", scalar(fields, "site", "__unregistered__")));
  if (text(row, "site") == "__unregistered__" &&
      !c.telemetry.sites_file.empty()) {
    thread_local std::map<std::string, std::string> hosts;
    thread_local std::string cached;
    thread_local struct stat previous{};
    struct stat current{};
    if (!stat(c.telemetry.sites_file.c_str(), &current)) {
      if (cached != c.telemetry.sites_file ||
          current.st_ino != previous.st_ino ||
          current.st_size != previous.st_size ||
          current.st_mtim.tv_sec != previous.st_mtim.tv_sec ||
          current.st_mtim.tv_nsec != previous.st_mtim.tv_nsec) {
        auto sites = site_catalog(c.telemetry.sites_file);
        std::map<std::string, std::string> replacement;
        for (size_t i = 0; i < json_object_array_length(sites.get()); i++) {
          auto site = own(
                   json_object_get(json_object_array_get_idx(sites.get(), i))),
               names = get(site, "hosts");
          for (size_t n = 0; n < json_object_array_length(names.get()); n++)
            replacement[str(own(
                json_object_get(json_object_array_get_idx(names.get(), n))))] =
                text(site, "id");
        }
        hosts = std::move(replacement);
        cached = c.telemetry.sites_file;
        previous = current;
      }
      auto match = hosts.find(host);
      if (match != hosts.end())
        put(row, "site", match->second);
    }
  }
  auto uri = scalar(fields, "uri", "/");
  if (uri.compare(0, 7, "http://") == 0 || uri.compare(0, 8, "https://") == 0) {
    auto at = uri.find('/', uri.find("://") + 3);
    uri = at == std::string::npos ? "/" : uri.substr(at);
  }
  auto query = uri.find_first_of("?#");
  if (query != std::string::npos)
    uri.resize(query);
  uri.erase(
      std::remove_if(uri.begin(), uri.end(),
                     [](unsigned char ch) { return ch < 32 || ch == 127; }),
      uri.end());
  if (uri.empty())
    uri = "/";
  put(row, "uri", uri);
  put(row, "method", scalar(fields, "method", "UNKNOWN"));
  unsigned status = std::min(999.0, numeric(fields, "status"));
  put(row, "status", uint64_t(status));
  put(row, "bytes",
      uint64_t(numeric(fields, "bytes") ? numeric(fields, "bytes")
                                        : numeric(fields, "body_bytes_sent")));
  json_object_object_add(
      row.get(), "duration_ms",
      json_object_new_double(1000 * (numeric(fields, "rt")
                                         ? numeric(fields, "rt")
                                         : numeric(fields, "request_time"))));
  std::string cache = scalar(fields, "cache", "NONE");
  std::transform(cache.begin(), cache.end(), cache.begin(),
                 [](unsigned char ch) { return std::toupper(ch); });
  put(row, "cache", cache);
  auto upstream = scalar(fields, "upstream_status", scalar(fields, "upstream"));
  bool origin = !upstream.empty() && upstream != "-";
  bool blocked = (status == 403 || status == 429) && !origin &&
                 cache != "HIT" && cache != "STALE" && cache != "UPDATING";
  put(row, "origin_seen", origin ? uint64_t(1) : uint64_t(0));
  put(row, "blocked", blocked ? uint64_t(1) : uint64_t(0));
  put(row, "block_reason",
      blocked ? (text(row, "site") == "__unregistered__" ? "域名访问控制"
                 : status == 429                         ? "限流拒绝"
                                                         : "边缘直接拒绝")
              : "");
  double origin_ms = 0;
  auto raw = scalar(fields, "urt", scalar(fields, "upstream_response_time"));
  for (size_t i = 0; i < raw.size();) {
    if (raw[i] < '0' || raw[i] > '9') {
      i++;
      continue;
    }
    double seconds = 0;
    while (i < raw.size() && raw[i] >= '0' && raw[i] <= '9')
      seconds = seconds * 10 + (raw[i++] - '0');
    if (i + 1 < raw.size() && raw[i] == '.' && raw[i + 1] >= '0' &&
        raw[i + 1] <= '9') {
      i++;
      double scale = .1;
      while (i < raw.size() && raw[i] >= '0' && raw[i] <= '9') {
        seconds += (raw[i++] - '0') * scale;
        scale *= .1;
      }
    }
    need(std::isfinite(seconds) && std::isfinite(origin_ms + seconds * 1000),
         STATE);
    origin_ms += seconds * 1000;
  }
  json_object_object_add(row.get(), "origin_ms",
                         json_object_new_double(origin_ms));
  put(row, "cache_layer", scalar(fields, "cache_layer", "unknown"));
  put(row, "country", scalar(fields, "country", "ZZ"));
  put(row, "asn", uint64_t(numeric(fields, "asn")));
  auto org = scalar(fields, "asn_org", "unknown");
  put(row, "asn_org", org);
  put(row, "operator", operator_name(org));
  put(row, "protocol",
      scalar(fields, "http_version", scalar(fields, "protocol", "unknown")));
  return row;
}
} // namespace logs
