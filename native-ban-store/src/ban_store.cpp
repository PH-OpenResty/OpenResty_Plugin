#include "ban_store.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ban_store {
namespace {
constexpr size_t header_size = 112, frame_size = 96, row_overhead = 160;
constexpr size_t max_frame = 64u * 1024u * 1024u,
                 max_value = 16u * 1024u * 1024u;
const char *names[] = {"meta",     "records",  "audit",           "producers",
                       "receipts", "requests", "evidence",        "fences",
                       "outbox",   "globals",  "origin_receipts", "origin_high",
                       "results"};
void check(bool condition, const char *error) {
  if (!condition)
    throw std::runtime_error(error);
}
size_t index(Table t) {
  auto n = static_cast<size_t>(t);
  check(n < table_count, "store_table");
  return n;
}
void put64(unsigned char *p, uint64_t value) {
  for (unsigned i = 0; i < 8; i++) {
    p[i] = value & 255;
    value >>= 8;
  }
}
uint64_t get64(const unsigned char *p) {
  uint64_t n = 0;
  for (unsigned i = 0; i < 8; i++)
    n |= uint64_t(p[i]) << (i * 8);
  return n;
}
void put32(unsigned char *p, uint32_t value) {
  for (unsigned i = 0; i < 4; i++) {
    p[i] = value & 255;
    value >>= 8;
  }
}
uint32_t get32(const unsigned char *p) {
  uint32_t n = 0;
  for (unsigned i = 0; i < 4; i++)
    n |= uint32_t(p[i]) << (i * 8);
  return n;
}
struct Digest {
  EVP_MD_CTX *value = EVP_MD_CTX_new();
  Digest() {
    check(value && EVP_DigestInit_ex(value, EVP_sha256(), nullptr) == 1,
          "store_digest");
  }
  ~Digest() { EVP_MD_CTX_free(value); }
  void add(const void *p, size_t n) {
    check(EVP_DigestUpdate(value, p, n) == 1, "store_digest");
  }
  std::array<unsigned char, 32> finish() {
    std::array<unsigned char, 32> out{};
    unsigned n = 0;
    check(EVP_DigestFinal_ex(value, out.data(), &n) == 1 && n == 32,
          "store_digest");
    return out;
  }
};
std::array<unsigned char, 32> digest(const void *p, size_t n) {
  Digest d;
  d.add(p, n);
  return d.finish();
}
uint32_t frame_header_checksum(const unsigned char *p) {
  std::array<unsigned char, 64> header{};
  memcpy(header.data(), p, 64);
  memset(header.data() + 28, 0, 4);
  auto sum = digest(header.data(), header.size());
  return get32(sum.data());
}
void read_all(int fd, void *p, size_t n) {
  size_t done = 0;
  while (done < n) {
    auto rc = read(fd, (char *)p + done, n - done);
    if (rc < 0 && errno == EINTR)
      continue;
    check(rc > 0, "store_read");
    done += static_cast<size_t>(rc);
  }
}
void write_all(int fd, const void *p, size_t n) {
  size_t done = 0;
  while (done < n) {
    auto rc = write(fd, (const char *)p + done, n - done);
    if (rc < 0 && errno == EINTR)
      continue;
    check(rc > 0, "store_write");
    done += static_cast<size_t>(rc);
  }
}
void private_file(int fd) {
  struct stat st{};
  check(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
            st.st_uid == geteuid() && st.st_nlink == 1 && !(st.st_mode & 077),
        "store_file_permissions");
}
int directory_open(const std::string &path) {
  check(path.size() > 1 && path[0] == '/' && path.back() != '/',
        "store_absolute_directory");
  int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  check(fd >= 0, "store_directory");
  try {
    size_t pos = 1;
    while (pos < path.size()) {
      size_t next = path.find('/', pos);
      auto part =
          path.substr(pos, next == std::string::npos ? next : next - pos);
      check(!part.empty() && part != "." && part != "..",
            "store_directory_component");
      int child = openat(fd, part.c_str(),
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      check(child >= 0, "store_directory");
      close(fd);
      fd = child;
      if (next == std::string::npos)
        break;
      pos = next + 1;
    }
    struct stat st{};
    check(!fstat(fd, &st) && st.st_uid == geteuid() && !(st.st_mode & 077),
          "store_directory_permissions");
    return fd;
  } catch (...) {
    close(fd);
    throw;
  }
}
std::array<unsigned char, 16> row_header(Table t, bool remove,
                                         const std::string &key,
                                         const std::string &value) {
  check(!key.empty() && key.size() <= 4096 && value.size() <= max_value,
        "store_row_bounds");
  std::array<unsigned char, 16> h{};
  h[0] = static_cast<unsigned char>(index(t));
  h[1] = remove ? 1 : 0;
  put32(h.data() + 4, static_cast<uint32_t>(key.size()));
  put64(h.data() + 8, remove ? 0 : value.size());
  return h;
}
} // namespace
Table table(const std::string &name) {
  for (size_t i = 0; i < table_count; i++)
    if (name == names[i])
      return static_cast<Table>(i);
  throw std::runtime_error("store_table");
}
const char *table_name(Table t) { return names[index(t)]; }
std::string number_key(uint64_t n) {
  auto s = std::to_string(n);
  return std::string(20 - s.size(), '0') + s;
}
bool Store::ordered(Table t) {
  return t == Table::Audit || t == Table::Evidence || t == Table::Outbox;
}
void Store::healthy() const { check(stats_.healthy, "store_poisoned"); }
size_t Store::pending_bytes() const {
  size_t total = 0;
  for (auto &p : pending_)
    total += p.bytes;
  return total;
}
Store::Store(Options options) : options_(std::move(options)) {
  check(options_.max_entries > 0 && options_.max_entries <= 16000000 &&
            options_.max_bytes >= 4096 && options_.checkpoint_bytes >= 1024 &&
            options_.max_log_bytes > options_.max_bytes,
        "store_options");
  stats_.persistent = options_.persistent;
  check(RAND_bytes(identity_.data(), identity_.size()) == 1, "store_random");
  if (!options_.persistent)
    return;
  try {
    directory_ = directory_open(options_.directory);
    lock_ = openat(directory_, "ban-store.lock",
                   O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    private_file(lock_);
    check(!flock(lock_, LOCK_EX | LOCK_NB), "store_already_open");
    file_ = openat(directory_, "ban-store.aof",
                   O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (file_ < 0) {
      check(errno == ENOENT, "store_open");
      write_checkpoint(true);
    } else {
      private_file(file_);
      load();
    }
  } catch (...) {
    if (file_ >= 0)
      close(file_);
    if (lock_ >= 0)
      close(lock_);
    if (directory_ >= 0)
      close(directory_);
    throw;
  }
}
Store::~Store() {
  if (file_ >= 0)
    close(file_);
  if (lock_ >= 0)
    close(lock_);
  if (directory_ >= 0)
    close(directory_);
}
const std::string *Store::base(Table t, const std::string &key) const {
  auto n = index(t);
  if (ordered(t)) {
    auto p = ordered_[n].find(key);
    return p == ordered_[n].end() ? nullptr : &p->second;
  }
  auto p = hashes_[n].find(key);
  return p == hashes_[n].end() ? nullptr : &p->second;
}
size_t Store::base_size(Table t) const {
  return ordered(t) ? ordered_[index(t)].size() : hashes_[index(t)].size();
}
std::optional<std::string> Store::get(Table t, const std::string &key) const {
  healthy();
  auto n = index(t);
  for (auto p = pending_.rbegin(); p != pending_.rend(); ++p) {
    auto found = p->puts[n].find(key);
    if (found != p->puts[n].end())
      return found->second;
    if (p->deletes[n].count(key))
      return {};
  }
  auto value = base(t, key);
  return value ? std::optional<std::string>(*value) : std::nullopt;
}
void Store::begin() {
  healthy();
  check(pending_.size() < 16, "store_transaction_depth");
  pending_.emplace_back();
}
void Store::rollback() noexcept {
  if (!pending_.empty())
    pending_.pop_back();
}
void Store::put(Table t, const std::string &key, const std::string &value) {
  healthy();
  (void)row_header(t, false, key, value);
  auto current = get(t, key);
  if (current && *current == value)
    return;
  bool automatic = pending_.empty();
  if (automatic)
    begin();
  try {
    auto n = index(t);
    auto &p = pending_.back();
    auto old = p.puts[n].find(key);
    size_t before = old != p.puts[n].end()
                        ? key.size() + old->second.size() + row_overhead
                    : p.deletes[n].count(key) ? key.size() + row_overhead
                                              : 0;
    size_t after = key.size() + value.size() + row_overhead,
           total = pending_bytes() - before;
    check(after <= options_.max_bytes - total, "store_pending_memory_limit");
    p.puts[n].insert_or_assign(key, value);
    p.bytes = p.bytes - before + after;
    pending_.back().deletes[n].erase(key);
    if (automatic)
      commit();
  } catch (...) {
    if (automatic)
      rollback();
    throw;
  }
}
void Store::erase(Table t, const std::string &key) {
  healthy();
  if (!get(t, key))
    return;
  bool automatic = pending_.empty();
  if (automatic)
    begin();
  try {
    auto n = index(t);
    auto &p = pending_.back();
    auto old = p.puts[n].find(key);
    size_t before = old != p.puts[n].end()
                        ? key.size() + old->second.size() + row_overhead
                    : p.deletes[n].count(key) ? key.size() + row_overhead
                                              : 0;
    size_t after = key.size() + row_overhead, total = pending_bytes() - before;
    check(after <= options_.max_bytes - total, "store_pending_memory_limit");
    pending_.back().deletes[n].insert(key);
    pending_.back().puts[n].erase(key);
    p.bytes = p.bytes - before + after;
    if (automatic)
      commit();
  } catch (...) {
    if (automatic)
      rollback();
    throw;
  }
}
std::vector<Store::Row> Store::rows(Table t) const {
  healthy();
  auto n = index(t);
  std::map<std::string, std::string> values;
  if (ordered(t))
    values = ordered_[n];
  else
    for (auto &r : hashes_[n])
      values.emplace(r);
  for (auto &p : pending_) {
    for (auto &key : p.deletes[n])
      values.erase(key);
    for (auto &r : p.puts[n])
      values[r.first] = r.second;
  }
  return {values.begin(), values.end()};
}
size_t Store::size(Table t) const {
  healthy();
  auto n = index(t);
  if (pending_.empty())
    return base_size(t);
  std::set<std::string> keys;
  for (auto &p : pending_) {
    for (auto &r : p.puts[n])
      keys.insert(r.first);
    keys.insert(p.deletes[n].begin(), p.deletes[n].end());
  }
  size_t count = base_size(t);
  for (auto &key : keys) {
    bool was = base(t, key) != nullptr, now = get(t, key).has_value();
    if (was && !now)
      --count;
    if (!was && now)
      ++count;
  }
  return count;
}
void Store::clear(Table t) {
  bool automatic = pending_.empty();
  if (automatic)
    begin();
  try {
    for (auto &r : rows(t))
      erase(t, r.first);
    if (automatic)
      commit();
  } catch (...) {
    if (automatic)
      rollback();
    throw;
  }
}
std::vector<Store::Row> Store::range(Table t, const std::string &lower,
                                     const std::string &upper,
                                     size_t limit) const {
  healthy();
  check(ordered(t), "store_ordered_partition_required");
  auto n = index(t);
  std::map<std::string, std::string> values;
  auto it = ordered_[n].lower_bound(lower);
  for (; it != ordered_[n].end() && (upper.empty() || it->first < upper) &&
         values.size() < limit;
       ++it) {
    auto value = get(t, it->first);
    if (value)
      values.emplace(it->first, std::move(*value));
  }
  for (auto &p : pending_)
    for (auto &r : p.puts[n])
      if (r.first >= lower && (upper.empty() || r.first < upper)) {
        auto value = get(t, r.first);
        if (value)
          values[r.first] = std::move(*value);
      }
  std::vector<Row> out;
  out.reserve(std::min(limit, values.size()));
  for (auto &r : values) {
    if (out.size() == limit)
      break;
    out.push_back(r);
  }
  return out;
}
std::string Store::encode(const Pending &p, uint32_t &count) const {
  std::string bytes;
  count = 0;
  auto add = [&](Table t, bool remove, const std::string &key,
                 const std::string &value) {
    auto h = row_header(t, remove, key, value);
    check(h.size() + key.size() + (remove ? 0 : value.size()) <=
              max_frame - bytes.size(),
          "store_transaction_too_large");
    bytes.append((char *)h.data(), h.size());
    bytes += key;
    if (!remove)
      bytes += value;
    count++;
  };
  for (size_t n = 0; n < table_count; n++) {
    auto t = static_cast<Table>(n);
    for (auto &key : p.deletes[n])
      add(t, true, key, "");
    for (auto &r : p.puts[n])
      add(t, false, r.first, r.second);
  }
  return bytes;
}
Store::Pending Store::decode(const std::string &bytes, uint32_t count) const {
  Pending p;
  size_t offset = 0;
  for (uint32_t i = 0; i < count; i++) {
    check(bytes.size() - offset >= 16, "store_record_corrupt");
    auto h = (const unsigned char *)bytes.data() + offset;
    offset += 16;
    check(h[0] < table_count && h[1] <= 1 && !h[2] && !h[3],
          "store_record_corrupt");
    size_t key = get32(h + 4);
    uint64_t value = get64(h + 8);
    check(key > 0 && key <= 4096 && value <= max_value &&
              key + value <= bytes.size() - offset && (!h[1] || !value),
          "store_record_corrupt");
    auto name = bytes.substr(offset, key);
    offset += key;
    auto n = h[0];
    check(!p.puts[n].count(name) && !p.deletes[n].count(name),
          "store_duplicate_mutation");
    if (h[1])
      p.deletes[n].insert(name);
    else
      p.puts[n].emplace(std::move(name), bytes.substr(offset, (size_t)value));
    offset += (size_t)value;
  }
  check(offset == bytes.size(), "store_record_corrupt");
  return p;
}
void Store::validate(const Pending &p, size_t &entries, size_t &bytes) const {
  entries = stats_.entries;
  bytes = stats_.bytes;
  for (size_t n = 0; n < table_count; n++) {
    auto t = static_cast<Table>(n);
    for (auto &key : p.deletes[n])
      if (auto old = base(t, key)) {
        --entries;
        bytes -= key.size() + old->size() + row_overhead;
      }
    for (auto &r : p.puts[n]) {
      if (auto old = base(t, r.first))
        bytes -= r.first.size() + old->size() + row_overhead;
      else
        ++entries;
      check(r.first.size() + r.second.size() + row_overhead <=
                options_.max_bytes - bytes,
            "store_memory_limit");
      bytes += r.first.size() + r.second.size() + row_overhead;
    }
  }
  check(entries <= options_.max_entries && bytes <= options_.max_bytes,
        "store_capacity");
}
void Store::prepare(const Pending &p, std::array<Ordered, table_count> &nodes) {
  for (size_t n = 0; n < table_count; n++) {
    auto t = static_cast<Table>(n);
    if (ordered(t)) {
      for (auto &r : p.puts[n])
        if (!base(t, r.first))
          nodes[n].emplace(r);
    } else if ((!p.puts[n].empty() && hashes_[n].bucket_count() <= 1) ||
               hashes_[n].size() + p.puts[n].size() >
                   hashes_[n].bucket_count() * hashes_[n].max_load_factor())
      hashes_[n].reserve(std::max(hashes_[n].size() + p.puts[n].size(),
                                  hashes_[n].size() * 2 + 1));
  }
}
void Store::publish(Pending &p,
                    std::array<Ordered, table_count> &nodes) noexcept {
  for (size_t n = 0; n < table_count; n++) {
    auto t = static_cast<Table>(n);
    if (ordered(t)) {
      for (auto &key : p.deletes[n])
        ordered_[n].erase(key);
      for (auto &r : p.puts[n]) {
        auto old = ordered_[n].find(r.first);
        if (old != ordered_[n].end())
          old->second.swap(r.second);
        else
          ordered_[n].insert(nodes[n].extract(r.first));
      }
    } else {
      for (auto &key : p.deletes[n])
        hashes_[n].erase(key);
      while (!p.puts[n].empty()) {
        auto it = p.puts[n].begin();
        auto old = hashes_[n].find(it->first);
        if (old != hashes_[n].end()) {
          old->second.swap(it->second);
          p.puts[n].erase(it);
        } else
          hashes_[n].insert(p.puts[n].extract(it));
      }
    }
  }
}
void Store::apply(Pending &p) {
  size_t entries, bytes;
  validate(p, entries, bytes);
  std::array<Ordered, table_count> nodes;
  prepare(p, nodes);
  publish(p, nodes);
  stats_.entries = entries;
  stats_.bytes = bytes;
}
void Store::commit() {
  healthy();
  check(!pending_.empty(), "store_no_transaction");
  if (pending_.size() > 1) {
    auto &parent = pending_[pending_.size() - 2];
    auto &child = pending_.back();
    for (size_t n = 0; n < table_count; n++)
      parent.puts[n].reserve(parent.puts[n].size() + child.puts[n].size());
    for (size_t n = 0; n < table_count; n++) {
      while (!child.deletes[n].empty()) {
        auto node = child.deletes[n].extract(child.deletes[n].begin());
        parent.puts[n].erase(node.value());
        parent.deletes[n].insert(std::move(node));
      }
      while (!child.puts[n].empty()) {
        auto it = child.puts[n].begin();
        parent.deletes[n].erase(it->first);
        auto old = parent.puts[n].find(it->first);
        if (old != parent.puts[n].end()) {
          old->second.swap(it->second);
          child.puts[n].erase(it);
        } else
          parent.puts[n].insert(child.puts[n].extract(it));
      }
    }
    parent.bytes = 0;
    for (size_t n = 0; n < table_count; n++) {
      for (auto &r : parent.puts[n])
        parent.bytes += r.first.size() + r.second.size() + row_overhead;
      for (auto &key : parent.deletes[n])
        parent.bytes += key.size() + row_overhead;
    }
    pending_.pop_back();
    return;
  }
  auto &p = pending_.back();
  uint32_t count = 0;
  std::string payload;
  if (options_.persistent)
    payload = encode(p, count);
  else {
    size_t equivalent = 0;
    auto add = [&](size_t size) {
      check(size <= max_frame - equivalent, "store_transaction_too_large");
      equivalent += size;
      count++;
    };
    for (size_t n = 0; n < table_count; n++) {
      for (auto &key : p.deletes[n])
        add(16 + key.size());
      for (auto &row : p.puts[n])
        add(16 + row.first.size() + row.second.size());
    }
  }
  if (!count) {
    pending_.pop_back();
    return;
  }
  size_t entries, bytes;
  validate(p, entries, bytes);
  std::array<Ordered, table_count> nodes;
  prepare(p, nodes);
  check(stats_.sequence < UINT64_MAX, "store_sequence_exhausted");
  if (options_.persistent) {
    std::array<unsigned char, frame_size> frame{};
    memcpy(frame.data(), "SBNTX001", 8);
    put64(frame.data() + 8, payload.size());
    put64(frame.data() + 16, stats_.sequence + 1);
    put32(frame.data() + 24, count);
    memcpy(frame.data() + 32, chain_.data(), chain_.size());
    put32(frame.data() + 28, frame_header_checksum(frame.data()));
    Digest d;
    d.add(frame.data(), 64);
    d.add(payload.data(), payload.size());
    auto sum = d.finish();
    memcpy(frame.data() + 64, sum.data(), 32);
    check(frame.size() + payload.size() <=
              options_.max_log_bytes - stats_.log_bytes,
          "store_log_limit");
    try {
      write_all(file_, frame.data(), frame.size());
      write_all(file_, payload.data(), payload.size());
      check(!fdatasync(file_), "store_sync");
      stats_.syncs++;
    } catch (...) {
      stats_.healthy = false;
      throw;
    }
    stats_.log_bytes += frame.size() + payload.size();
    journal_bytes_ += frame.size() + payload.size();
    chain_ = sum;
  }
  publish(p, nodes);
  pending_.pop_back();
  stats_.entries = entries;
  stats_.bytes = bytes;
  stats_.sequence++;
  stats_.transactions++;
  if (options_.persistent && journal_bytes_ >= options_.checkpoint_bytes) {
    try {
      checkpoint();
      stats_.checkpoint_error.clear();
    } catch (const std::exception &e) {
      stats_.checkpoint_error = e.what();
      if (!stats_.healthy)
        throw;
    }
  }
}
void Store::load() {
  struct stat st{};
  check(!fstat(file_, &st) && st.st_size >= static_cast<off_t>(header_size) &&
            uint64_t(st.st_size) <= options_.max_log_bytes,
        "store_header_corrupt");
  std::array<unsigned char, header_size> h{};
  read_all(file_, h.data(), h.size());
  auto header_hash = digest(h.data(), 80);
  check(!memcmp(h.data(), "SBNST001", 8) && get32(h.data() + 8) == 1 &&
            !memcmp(header_hash.data(), h.data() + 80, 32),
        "store_header_corrupt");
  uint32_t count = get32(h.data() + 12);
  uint64_t length = get64(h.data() + 16);
  check(count <= options_.max_entries && length <= options_.max_bytes &&
            length <= uint64_t(st.st_size) - header_size,
        "store_snapshot_bounds");
  memcpy(identity_.data(), h.data() + 32, 16);
  stats_.sequence = get64(h.data() + 24);
  Digest d;
  size_t remaining = (size_t)length;
  for (uint32_t i = 0; i < count; i++) {
    std::array<unsigned char, 16> r{};
    check(remaining >= 16, "store_snapshot_corrupt");
    read_all(file_, r.data(), 16);
    remaining -= 16;
    d.add(r.data(), 16);
    check(r[0] < table_count && !r[1] && !r[2] && !r[3],
          "store_snapshot_corrupt");
    size_t k = get32(r.data() + 4);
    uint64_t v = get64(r.data() + 8);
    check(k > 0 && k <= 4096 && v <= max_value && k + v <= remaining,
          "store_snapshot_corrupt");
    std::string key(k, '\0'), value((size_t)v, '\0');
    read_all(file_, key.data(), k);
    read_all(file_, value.data(), value.size());
    d.add(key.data(), k);
    d.add(value.data(), value.size());
    remaining -= k + value.size();
    auto t = static_cast<Table>(r[0]);
    check(!base(t, key), "store_snapshot_duplicate");
    size_t charge = k + value.size() + row_overhead;
    check(charge <= options_.max_bytes - stats_.bytes, "store_memory_limit");
    stats_.bytes += charge;
    stats_.entries++;
    if (ordered(t))
      ordered_[r[0]].emplace(std::move(key), std::move(value));
    else
      hashes_[r[0]].emplace(std::move(key), std::move(value));
  }
  auto sum = d.finish();
  check(!remaining && !memcmp(sum.data(), h.data() + 48, 32),
        "store_snapshot_checksum");
  memcpy(chain_.data(), h.data() + 80, 32);
  size_t offset = header_size + (size_t)length;
  auto truncate_tail = [&]() {
    stats_.recovered_tail_bytes = (size_t)st.st_size - offset;
    check(!ftruncate(file_, (off_t)offset) && !fdatasync(file_),
          "store_tail_recovery");
    stats_.syncs++;
  };
  while (offset < (size_t)st.st_size) {
    if ((size_t)st.st_size - offset < frame_size) {
      truncate_tail();
      break;
    }
    std::array<unsigned char, frame_size> frame{};
    read_all(file_, frame.data(), frame.size());
    uint64_t size = get64(frame.data() + 8), seq = get64(frame.data() + 16);
    uint32_t items = get32(frame.data() + 24);
    check(!memcmp(frame.data(), "SBNTX001", 8) &&
              get32(frame.data() + 28) == frame_header_checksum(frame.data()) &&
              size <= max_frame && items > 0 && items <= size / 17 &&
              items <= options_.max_bytes / row_overhead &&
              stats_.sequence < UINT64_MAX && seq == stats_.sequence + 1 &&
              !memcmp(frame.data() + 32, chain_.data(), 32),
          "store_frame_corrupt");
    if (size > (size_t)st.st_size - offset - frame_size) {
      truncate_tail();
      break;
    }
    std::string payload((size_t)size, '\0');
    read_all(file_, payload.data(), payload.size());
    Digest tx;
    tx.add(frame.data(), 64);
    tx.add(payload.data(), payload.size());
    auto hash = tx.finish();
    check(!memcmp(hash.data(), frame.data() + 64, 32), "store_frame_checksum");
    auto pending = decode(payload, items);
    apply(pending);
    chain_ = hash;
    stats_.sequence = seq;
    offset += frame_size + payload.size();
  }
  check(lseek(file_, 0, SEEK_END) == (off_t)offset, "store_seek");
  stats_.log_bytes = offset;
  journal_bytes_ = offset - header_size - (size_t)length;
}
void Store::write_checkpoint(bool initial) {
  check(directory_ >= 0, "store_directory");
  std::array<unsigned char, header_size> h{};
  memcpy(h.data(), "SBNST001", 8);
  put32(h.data() + 8, 1);
  put32(h.data() + 12, static_cast<uint32_t>(stats_.entries));
  put64(h.data() + 24, stats_.sequence);
  memcpy(h.data() + 32, identity_.data(), 16);
  unsigned char random[8];
  check(RAND_bytes(random, sizeof(random)) == 1, "store_random");
  std::string name = ".ban-store-";
  for (auto n : random) {
    name += "0123456789abcdef"[n >> 4];
    name += "0123456789abcdef"[n & 15];
  }
  name += ".tmp";
  int fd = openat(directory_, name.c_str(),
                  O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  check(fd >= 0, "store_checkpoint_open");
  bool renamed = false;
  try {
    write_all(fd, h.data(), h.size());
    Digest d;
    size_t bytes = 0;
    std::string buffer;
    buffer.reserve(65536);
    auto append = [&](const void *p, size_t n) {
      if (n > 65536) {
        if (!buffer.empty()) {
          write_all(fd, buffer.data(), buffer.size());
          buffer.clear();
        }
        write_all(fd, p, n);
        return;
      }
      if (buffer.size() + n > 65536) {
        write_all(fd, buffer.data(), buffer.size());
        buffer.clear();
      }
      buffer.append((const char *)p, n);
    };
    auto emit = [&](Table t, const auto &r) {
      auto entry = row_header(t, false, r.first, r.second);
      append(entry.data(), entry.size());
      append(r.first.data(), r.first.size());
      append(r.second.data(), r.second.size());
      d.add(entry.data(), entry.size());
      d.add(r.first.data(), r.first.size());
      d.add(r.second.data(), r.second.size());
      bytes += entry.size() + r.first.size() + r.second.size();
    };
    for (size_t n = 0; n < table_count; n++) {
      auto t = static_cast<Table>(n);
      if (ordered(t))
        for (auto &r : ordered_[n])
          emit(t, r);
      else
        for (auto &r : hashes_[n])
          emit(t, r);
    }
    if (!buffer.empty())
      write_all(fd, buffer.data(), buffer.size());
    put64(h.data() + 16, bytes);
    auto sum = d.finish();
    memcpy(h.data() + 48, sum.data(), 32);
    auto head = digest(h.data(), 80);
    memcpy(h.data() + 80, head.data(), 32);
    check(lseek(fd, 0, SEEK_SET) == 0, "store_checkpoint_seek");
    write_all(fd, h.data(), h.size());
    check(!fdatasync(fd), "store_checkpoint_sync");
    stats_.syncs++;
    if (initial) {
      struct stat st{};
      check(fstatat(directory_, "ban-store.aof", &st, AT_SYMLINK_NOFOLLOW) <
                    0 &&
                errno == ENOENT,
            "store_target_exists");
    }
    check(!renameat(directory_, name.c_str(), directory_, "ban-store.aof"),
          "store_checkpoint_rename");
    renamed = true;
    check(!fsync(directory_), "store_directory_sync");
    if (file_ >= 0)
      close(file_);
    file_ = fd;
    fd = -1;
    check(lseek(file_, 0, SEEK_END) == (off_t)(header_size + bytes),
          "store_checkpoint_seek");
    chain_ = head;
    stats_.log_bytes = header_size + bytes;
    journal_bytes_ = 0;
    stats_.checkpoints++;
  } catch (...) {
    if (renamed)
      stats_.healthy = false;
    if (fd >= 0)
      close(fd);
    unlinkat(directory_, name.c_str(), 0);
    throw;
  }
}
void Store::checkpoint() {
  healthy();
  check(pending_.empty(), "store_checkpoint_in_transaction");
  if (options_.persistent)
    write_checkpoint(false);
}
} // namespace ban_store
