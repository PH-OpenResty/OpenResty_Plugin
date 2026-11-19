#include "log_sync.hpp"
#include <algorithm>
#include <cctype>

namespace logs {
static std::string credential(const std::string &path) {
  if (path.empty())
    return "";
  auto value = read_file(path, 16384, true);
  if (!value.empty() && value.back() == '\n')
    value.pop_back();
  if (!value.empty() && value.back() == '\r')
    value.pop_back();
  need(!value.empty() &&
           value.find_first_of("\r\n\0", 0, 3) == std::string::npos,
       CONFIG);
  return value;
}
struct Response {
  std::string body;
  size_t max;
};
static size_t receive(char *bytes, size_t size, size_t count, void *data) {
  auto *r = static_cast<Response *>(data);
  if (size && count > SIZE_MAX / size)
    return 0;
  size_t n = size * count;
  if (n > r->max - r->body.size())
    return 0;
  r->body.append(bytes, n);
  return n;
}
bool send(const Config &conf, const Sink &sink, const J &events,
          const std::string &batch) {
  std::string body, url = sink.endpoint;
  size_t count = json_object_array_length(events.get());
  CURL *raw = curl_easy_init();
  need(raw != nullptr, TRANSPORT);
  auto handle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(
      raw, curl_easy_cleanup);
  if (sink.type == "elasticsearch") {
    url += "/" + sink.index + "/_bulk";
    for (size_t i = 0; i < count; i++) {
      auto event =
          own(json_object_get(json_object_array_get_idx(events.get(), i)));
      auto document = copy(event);
      auto fields = text(event, "fields_json");
      if (!fields.empty())
        put(document, "fields", parse(fields));
      if (text(event, "kind") == "metrics" && !fields.empty())
        put(document, "metrics", parse(fields));
      auto normalized = text(event, "normalized_json");
      if (!normalized.empty())
        put(document, "normalized", parse(normalized));
      auto item = obj(), index = obj();
      put(index, "_id", text(event, "event_id"));
      put(item, "index", index);
      body += dump(item) + "\n" + dump(document) + "\n";
    }
  } else {
    std::string query = "INSERT INTO " + sink.database + "." + sink.table +
                        " FORMAT JSONEachRow";
    char *encoded =
        curl_easy_escape(raw, query.c_str(), static_cast<int>(query.size()));
    need(encoded != nullptr, TRANSPORT);
    url +=
        "/?query=" + std::string(encoded) +
        "&wait_end_of_query=1&async_insert=0&input_format_skip_unknown_fields=0"
        "&date_time_input_format=best_effort&insert_deduplication_token=" +
        batch;
    curl_free(encoded);
    for (size_t i = 0; i < count; i++)
      body += json_object_to_json_string_ext(
                  json_object_array_get_idx(events.get(), i),
                  JSON_C_TO_STRING_PLAIN) +
              std::string("\n");
  }
  curl_slist *headers = nullptr;
  headers =
      curl_slist_append(headers, sink.type == "elasticsearch"
                                     ? "Content-Type: application/x-ndjson"
                                     : "Content-Type: application/x-ndjson");
  headers = curl_slist_append(headers, "Expect:");
  auto authorization = credential(sink.authorization_file);
  if (!authorization.empty())
    headers =
        curl_slist_append(headers, ("Authorization: " + authorization).c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> header_owner(
      headers, curl_slist_free_all);
  auto username = credential(sink.username_file),
       password = credential(sink.password_file);
  Response response{{}, conf.response_bytes};
  curl_easy_setopt(raw, CURLOPT_URL, url.c_str());
  curl_easy_setopt(raw, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(raw, CURLOPT_POST, 1L);
  curl_easy_setopt(raw, CURLOPT_POSTFIELDS, body.data());
  curl_easy_setopt(raw, CURLOPT_POSTFIELDSIZE_LARGE,
                   static_cast<curl_off_t>(body.size()));
  curl_easy_setopt(raw, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(raw, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(raw, CURLOPT_TIMEOUT_MS, static_cast<long>(conf.timeout_ms));
  curl_easy_setopt(raw, CURLOPT_CONNECTTIMEOUT_MS,
                   static_cast<long>(conf.connect_ms));
  curl_easy_setopt(raw, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(raw, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(raw, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(raw, CURLOPT_PROXY, "");
  curl_easy_setopt(raw, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(raw, CURLOPT_SSL_VERIFYHOST, 2L);
  if (conf.stop) {
    curl_easy_setopt(raw, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(raw, CURLOPT_XFERINFODATA,
                     const_cast<std::atomic<bool> *>(conf.stop));
    curl_easy_setopt(
        raw, CURLOPT_XFERINFOFUNCTION,
        +[](void *p, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
          return static_cast<std::atomic<bool> *>(p)->load() ? 1 : 0;
        });
  }
  if (!sink.ca_file.empty())
    curl_easy_setopt(raw, CURLOPT_CAINFO, sink.ca_file.c_str());
  if (!username.empty()) {
    curl_easy_setopt(raw, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(raw, CURLOPT_PASSWORD, password.c_str());
    curl_easy_setopt(raw, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  }
  need(curl_easy_perform(raw) == CURLE_OK, TRANSPORT);
  long status = 0;
  curl_easy_getinfo(raw, CURLINFO_RESPONSE_CODE, &status);
  need(status >= 200 && status < 300, BACKEND);
  if (sink.type == "clickhouse") {
    need(std::all_of(response.body.begin(), response.body.end(),
                     [](unsigned char c) { return std::isspace(c); }),
         BACKEND);
    return true;
  }
  auto result = parse(response.body), items = get(result, "items");
  need(json_object_is_type(items.get(), json_type_array) &&
           json_object_array_length(items.get()) == count,
       BACKEND);
  need(!flag(result, "errors", true), BACKEND);
  for (size_t i = 0; i < count; i++) {
    auto item = own(json_object_get(json_object_array_get_idx(items.get(), i)));
    auto index = get(item, "index");
    auto event =
        own(json_object_get(json_object_array_get_idx(events.get(), i)));
    auto code = number(index, "status");
    need(code >= 200 && code < 300 &&
             text(index, "_id") == text(event, "event_id"),
         BACKEND);
  }
  return true;
}
std::string fetch_status(const Config &conf, const StatusSource &source) {
  CURL *raw = curl_easy_init();
  need(raw != nullptr, TRANSPORT);
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(raw,
                                                             curl_easy_cleanup);
  std::string url =
      source.socket.empty() ? source.url : "http://localhost" + source.path;
  Response response{{}, conf.response_bytes};
  curl_slist *headers = nullptr;
  auto authorization = credential(source.authorization_file);
  if (!authorization.empty())
    headers =
        curl_slist_append(headers, ("Authorization: " + authorization).c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> owner(
      headers, curl_slist_free_all);
  curl_easy_setopt(raw, CURLOPT_URL, url.c_str());
  curl_easy_setopt(raw, CURLOPT_HTTPHEADER, headers);
  if (!source.socket.empty())
    curl_easy_setopt(raw, CURLOPT_UNIX_SOCKET_PATH, source.socket.c_str());
  curl_easy_setopt(raw, CURLOPT_TIMEOUT_MS, 1000L);
  curl_easy_setopt(raw, CURLOPT_CONNECTTIMEOUT_MS, 500L);
  curl_easy_setopt(raw, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(raw, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(raw, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(raw, CURLOPT_PROXY, "");
  curl_easy_setopt(raw, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(raw, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(raw, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(raw, CURLOPT_WRITEDATA, &response);
  need(curl_easy_perform(raw) == CURLE_OK, TRANSPORT);
  long status = 0;
  curl_easy_getinfo(raw, CURLINFO_RESPONSE_CODE, &status);
  need(status == 200, BACKEND);
  return response.body;
}
} // namespace logs
