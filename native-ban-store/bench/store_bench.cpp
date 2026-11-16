#include "ban_store.hpp"
#include <chrono>
#include <cstdio>
#include <iostream>
#include <random>
#include <sys/resource.h>
using namespace ban_store;
using Clock = std::chrono::steady_clock;
static double milliseconds(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}
static std::string key(size_t n) {
  char out[64];
  snprintf(out, sizeof(out), "bench|2001:db8::%zx", n + 1);
  return out;
}
int main(int argc, char **argv) {
  try {
    if (argc != 4)
      return 2;
    Options options;
    options.directory = argv[1];
    options.persistent = std::string(argv[2]) == "persistent";
    size_t count = std::stoull(argv[3]);
    if (!count || count > 1000000)
      throw std::runtime_error("bench_count");
    const size_t batch = 1024;
    double insert_ms, lookup_ms, erase_ms, checkpoint_ms = 0, recovery_ms = 0;
    Stats stats;
    uint64_t checksum = 0;
    {
      Store store(options);
      auto start = Clock::now();
      for (size_t offset = 0; offset < count; offset += batch) {
        store.begin();
        for (size_t i = offset; i < std::min(offset + batch, count); i++) {
          auto identity = key(i);
          auto ip = identity.substr(6);
          store.put(Table::Records, identity,
                    "{\"ip\":\"" + ip +
                        "\",\"scope\":\"bench\",\"expires\":\"1900000000000\","
                        "\"ban_id\":\"00000000000000000000000000000001\"}");
        }
        store.commit();
      }
      insert_ms = milliseconds(start);
      if (store.size(Table::Records) != count)
        throw std::runtime_error("bench_insert");
      std::mt19937_64 random(1234);
      start = Clock::now();
      for (size_t i = 0; i < 100000; i++) {
        auto value = store.get(Table::Records, key(random() % count));
        if (!value)
          throw std::runtime_error("bench_lookup");
        checksum += value->size();
      }
      lookup_ms = milliseconds(start);
      start = Clock::now();
      for (size_t offset = 0; offset < count; offset += batch) {
        store.begin();
        for (size_t i = offset; i < std::min(offset + batch, count); i += 2)
          store.erase(Table::Records, key(i));
        store.commit();
      }
      erase_ms = milliseconds(start);
      start = Clock::now();
      store.checkpoint();
      checkpoint_ms = milliseconds(start);
      stats = store.stats();
    }
    if (options.persistent) {
      auto start = Clock::now();
      Store recovered(options);
      recovery_ms = milliseconds(start);
      if (recovered.size(Table::Records) != count / 2)
        throw std::runtime_error("bench_recovery");
      for (size_t i = 0; i < std::min<size_t>(count, 2000); i++)
        if (recovered.get(Table::Records, key(i)).has_value() != (i % 2 == 1))
          throw std::runtime_error("bench_recovered_value");
    }
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    std::cout << "{\"mode\":\"" << argv[2] << "\",\"ips\":" << count
              << ",\"batch\":" << batch << ",\"insert_ms\":" << insert_ms
              << ",\"lookup_100k_ms\":" << lookup_ms
              << ",\"erase_half_ms\":" << erase_ms
              << ",\"checkpoint_ms\":" << checkpoint_ms
              << ",\"recovery_ms\":" << recovery_ms
              << ",\"transactions\":" << stats.transactions
              << ",\"data_syncs\":" << stats.syncs
              << ",\"checkpoints\":" << stats.checkpoints
              << ",\"accounted_live_bytes\":" << stats.bytes
              << ",\"peak_rss_kib\":" << usage.ru_maxrss
              << ",\"checksum\":" << checksum << "}" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
