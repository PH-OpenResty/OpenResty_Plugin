#include "ban_store.hpp"
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace ban_store;
static unsigned checks;
static void expect(bool ok, const std::string &message) {
  if (!ok)
    throw std::runtime_error(message);
  ++checks;
  std::cout << "PASS " << message << std::endl;
}
template <class F>
static void rejected(F callback, const std::string &message) {
  bool threw = false;
  try {
    callback();
  } catch (const std::exception &) {
    threw = true;
  }
  expect(threw, message);
}
static std::string read(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), {}};
}
static void write(const std::string &path, const std::string &bytes) {
  std::ofstream out(path, std::ios::binary);
  out.write(bytes.data(), bytes.size());
  out.close();
  chmod(path.c_str(), 0600);
}
static Options directory(const std::string &path) {
  if (mkdir(path.c_str(), 0700) && errno != EEXIST)
    throw std::runtime_error("fixture_directory");
  Options o;
  o.directory = path;
  return o;
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      return 2;
    std::string root = argv[1];
    Options memory;
    memory.persistent = false;
    memory.directory = root + "/never-created";
    {
      Store s(memory);
      s.put(Table::Records, "site|198.51.100.1", "original");
      expect(s.get(Table::Records, "site|198.51.100.1") == "original",
             "hash lookup returns original IP value");
      s.begin();
      s.put(Table::Records, "site|198.51.100.1", "changed");
      s.put(Table::Records, "site|2001:db8::1", "ipv6");
      s.rollback();
      expect(s.size(Table::Records) == 1 &&
                 s.get(Table::Records, "site|198.51.100.1") == "original",
             "rollback changes only the current transaction");
      s.begin();
      s.put(Table::Meta, "outer", "1");
      s.begin();
      s.put(Table::Meta, "inner", "2");
      s.commit();
      s.rollback();
      expect(!s.get(Table::Meta, "outer") && !s.get(Table::Meta, "inner"),
             "outer rollback includes a committed savepoint");
      s.begin();
      s.put(Table::Meta, "outer", "1");
      s.begin();
      s.erase(Table::Meta, "outer");
      s.rollback();
      s.commit();
      expect(s.get(Table::Meta, "outer") == "1",
             "savepoint rollback preserves its parent");
      s.begin();
      for (unsigned n = 0; n < 20; n++)
        s.put(Table::Audit, number_key(n), std::to_string(n));
      s.commit();
      s.begin();
      s.erase(Table::Audit, number_key(5));
      s.put(Table::Audit, number_key(7), "updated");
      auto r = s.range(Table::Audit, number_key(5), number_key(10), 2);
      expect(
          r.size() == 2 && r[0].first == number_key(6) &&
              r[1].second == "updated",
          "ordered range merges deletes and updates before applying a limit");
      s.rollback();
      rejected([&] { s.put(Table::Records, std::string(4097, 'x'), "x"); },
               "key limits reject oversized identities");
      s.checkpoint();
      expect(s.stats().syncs == 0 &&
                 access(memory.directory.c_str(), F_OK) != 0,
             "memory mode does not open state files or synchronize storage");
    }
    {
      Store s(memory);
      expect(s.size(Table::Records) == 0,
             "new memory instance starts without IP state");
    }
    {
      Options small = memory;
      small.max_entries = 2;
      small.max_bytes = 4096;
      Store s(small);
      s.put(Table::Records, "one", "1");
      s.begin();
      s.put(Table::Records, "two", "2");
      s.put(Table::Records, "three", "3");
      rejected([&] { s.commit(); }, "capacity rejects a whole transaction");
      s.rollback();
      expect(s.size(Table::Records) == 1,
             "rejected transaction publishes no partial state");
      rejected(
          [&] { s.put(Table::Records, "oversized", std::string(5000, 'v')); },
          "pending allocation respects the memory budget before commit");
      expect(!s.get(Table::Records, "oversized"),
             "pending memory rejection leaves the live index intact");
    }
    auto o = directory(root + "/durable");
    std::string first, second;
    size_t cut;
    {
      Store s(o);
      auto syncs = s.stats().syncs;
      s.begin();
      s.put(Table::Records, "site|198.51.100.1", "v1");
      s.put(Table::Fences, "198.51.100.2", "fixed");
      s.put(Table::Meta, "revision", "7");
      s.commit();
      expect(s.stats().syncs == syncs + 1,
             "batch commit uses one data synchronization");
      s.put(Table::Meta, "revision", "7");
      expect(s.stats().syncs == syncs + 1,
             "unchanged value avoids journal and synchronization work");
      first = read(o.directory + "/ban-store.aof");
      cut = first.size();
      s.begin();
      s.put(Table::Records, "site|198.51.100.1", "v2");
      s.erase(Table::Fences, "198.51.100.2");
      s.commit();
      second = read(o.directory + "/ban-store.aof");
      rejected([&] { Store other(o); },
               "writer lock rejects a second store owner");
    }
    {
      Store s(o);
      expect(s.get(Table::Records, "site|198.51.100.1") == "v2" &&
                 !s.get(Table::Fences, "198.51.100.2") &&
                 s.get(Table::Meta, "revision") == "7",
             "restart recovers atomic inserts updates and deletes");
    }
    for (size_t n :
         {size_t(1), size_t(95), size_t(96), second.size() - cut - 1}) {
      auto torn = directory(root + "/tail-" + std::to_string(n));
      write(torn.directory + "/ban-store.aof", second.substr(0, cut + n));
      Store s(torn);
      expect(s.get(Table::Records, "site|198.51.100.1") == "v1" &&
                 s.get(Table::Fences, "198.51.100.2") == "fixed" &&
                 s.stats().recovered_tail_bytes == n,
             "uncommitted torn tail is removed at cut " + std::to_string(n));
      s.put(Table::Meta, "after-recovery", "ok");
    }
    {
      auto corrupt = directory(root + "/corrupt");
      auto data = second;
      data[cut + 96 + 17] ^= 1;
      write(corrupt.directory + "/ban-store.aof", data);
      rejected([&] { Store s(corrupt); }, "complete frame checksum corruption "
                                          "is rejected instead of discarded");
      data = second;
      data[cut + 9] ^= 1;
      write(corrupt.directory + "/ban-store.aof", data);
      rejected([&] { Store s(corrupt); }, "corrupted transaction length cannot "
                                          "masquerade as an incomplete tail");
      data = second;
      data[24] ^= 1;
      write(corrupt.directory + "/ban-store.aof", data);
      rejected([&] { Store s(corrupt); },
               "snapshot header sequence corruption fails validation");
    }
    {
      auto compact = directory(root + "/compact");
      compact.checkpoint_bytes = 1024;
      {
        Store s(compact);
        for (unsigned i = 0; i < 200; i++) {
          s.begin();
          s.put(Table::Records, "ip-" + std::to_string(i),
                std::string(40, 'v'));
          s.put(Table::Meta, "high", std::to_string(i));
          s.commit();
        }
        expect(s.stats().checkpoints > 1,
               "automatic checkpoints compact a growing append log");
        s.checkpoint();
      }
      Store s(compact);
      expect(s.size(Table::Records) == 200 &&
                 s.get(Table::Meta, "high") == "199",
             "checkpoint preserves all live IPs and high watermarks");
      s.begin();
      for (unsigned i = 0; i < 100; i++)
        s.erase(Table::Records, "ip-" + std::to_string(i));
      s.commit();
      s.checkpoint();
      expect(s.size(Table::Records) == 100,
             "batch deletion remains valid after checkpoint");
    }
    {
      auto permissions = directory(root + "/permissions");
      {
        Store s(permissions);
      }
      chmod((permissions.directory + "/ban-store.aof").c_str(), 0644);
      rejected([&] { Store s(permissions); },
               "public state file permissions are rejected");
      auto links = directory(root + "/links");
      symlink((o.directory + "/ban-store.aof").c_str(),
              (links.directory + "/ban-store.aof").c_str());
      rejected([&] { Store s(links); }, "state file symlink is rejected");
      symlink(o.directory.c_str(), (root + "/parent-link").c_str());
      auto linked = o;
      linked.directory = root + "/parent-link";
      rejected([&] { Store s(linked); },
               "parent directory symlink is rejected");
    }
    std::cout << "CHECKS " << checks << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
