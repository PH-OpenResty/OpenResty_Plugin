#ifndef SCDN_BAN_STORE_HPP
#define SCDN_BAN_STORE_HPP
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

// Ban-only state partitions. No SQL, command parser, network listener or Redis
// dependency. The owning Agent serializes access, including transactions.
namespace ban_store {
enum class Table : uint8_t {
  Meta,
  Records,
  Audit,
  Producers,
  Receipts,
  Requests,
  Evidence,
  Fences,
  Outbox,
  Globals,
  OriginReceipts,
  OriginHigh,
  Results,
  Count
};
constexpr size_t table_count = static_cast<size_t>(Table::Count);
Table table(const std::string &name);
const char *table_name(Table value);
std::string number_key(uint64_t number);

struct Options {
  bool persistent = true;
  std::string directory;
  size_t max_entries = 1048576;
  size_t max_bytes = 512u * 1024u * 1024u;
  size_t checkpoint_bytes = 64u * 1024u * 1024u;
  size_t max_log_bytes = 2ull * 1024u * 1024u * 1024u;
};
struct Stats {
  uint64_t sequence = 0, transactions = 0, syncs = 0, checkpoints = 0;
  uint64_t recovered_tail_bytes = 0;
  size_t entries = 0, bytes = 0, log_bytes = 0;
  bool persistent = false, healthy = true;
  std::string checkpoint_error;
};
class Store {
public:
  using Row = std::pair<std::string, std::string>;
  explicit Store(Options options);
  ~Store();
  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;
  std::optional<std::string> get(Table t, const std::string &key) const;
  void put(Table t, const std::string &key, const std::string &value);
  void erase(Table t, const std::string &key);
  void clear(Table t);
  size_t size(Table t) const;
  std::vector<Row> rows(Table t) const;
  // Audit/outbox/evidence use ordered indexes; other point lookups use hashes.
  std::vector<Row> range(Table t, const std::string &lower,
                         const std::string &upper = "",
                         size_t limit = SIZE_MAX) const;
  void begin();
  void commit();
  void rollback() noexcept;
  bool in_transaction() const { return !pending_.empty(); }
  void checkpoint();
  const Stats &stats() const { return stats_; }

private:
  using Hash = std::unordered_map<std::string, std::string>;
  using Ordered = std::map<std::string, std::string>;
  struct Pending {
    size_t bytes = 0;
    std::array<Hash, table_count> puts;
    std::array<std::set<std::string>, table_count> deletes;
  };
  Options options_;
  Stats stats_;
  std::array<Hash, table_count> hashes_;
  std::array<Ordered, table_count> ordered_;
  std::vector<Pending> pending_;
  int directory_ = -1, lock_ = -1, file_ = -1;
  size_t journal_bytes_ = 0;
  std::array<unsigned char, 16> identity_{};
  std::array<unsigned char, 32> chain_{};
  static bool ordered(Table t);
  const std::string *base(Table t, const std::string &key) const;
  size_t base_size(Table t) const;
  void healthy() const;
  size_t pending_bytes() const;
  void load();
  void apply(Pending &pending);
  std::string encode(const Pending &pending, uint32_t &count) const;
  Pending decode(const std::string &bytes, uint32_t count) const;
  void validate(const Pending &pending, size_t &entries, size_t &bytes) const;
  void prepare(const Pending &pending, std::array<Ordered, table_count> &nodes);
  void publish(Pending &pending,
               std::array<Ordered, table_count> &nodes) noexcept;
  void write_checkpoint(bool initial);
};
} // namespace ban_store
#endif
