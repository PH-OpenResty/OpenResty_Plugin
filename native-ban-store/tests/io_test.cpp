#include "ban_store.hpp"
#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace ban_store;
static int write_budget = -1;
static bool fail_sync, fail_rename, fail_directory_sync;
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" int __real_fdatasync(int);
extern "C" int __real_fsync(int);
extern "C" int __real_renameat(int, const char *, int, const char *);
extern "C" ssize_t __wrap_write(int fd, const void *p, size_t n) {
  if (write_budget == 0) {
    errno = EIO;
    return -1;
  }
  if (write_budget > 0) {
    n = std::min(n, (size_t)write_budget);
    write_budget -= (int)n;
  }
  return __real_write(fd, p, n);
}
extern "C" int __wrap_fdatasync(int fd) {
  if (fail_sync) {
    errno = EIO;
    return -1;
  }
  return __real_fdatasync(fd);
}
extern "C" int __wrap_fsync(int fd) {
  struct stat st{};
  if (fail_directory_sync && !fstat(fd, &st) && S_ISDIR(st.st_mode)) {
    errno = EIO;
    return -1;
  }
  return __real_fsync(fd);
}
extern "C" int __wrap_renameat(int a, const char *b, int c, const char *d) {
  if (fail_rename) {
    errno = EIO;
    return -1;
  }
  return __real_renameat(a, b, c, d);
}
static unsigned checks;
static void expect(bool v, const char *name) {
  if (!v)
    throw std::runtime_error(name);
  checks++;
  std::cout << "PASS " << name << std::endl;
}
template <class F> static void fails(F f, const char *name) {
  bool error = false;
  try {
    f();
  } catch (const std::exception &) {
    error = true;
  }
  expect(error, name);
}
static Options options(const std::string &path) {
  if (mkdir(path.c_str(), 0700))
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
    auto partial = options(root + "/partial");
    {
      Store s(partial);
      s.put(Table::Records, "old", "fixed");
      write_budget = 10;
      fails([&] { s.put(Table::Records, "new", "pending"); },
            "short journal write cannot report commit success");
      write_budget = -1;
      expect(!s.stats().healthy,
             "I/O failure poisons the writer until recovery");
      fails([&] { s.put(Table::Records, "another", "x"); },
            "poisoned writer rejects additional changes");
    }
    {
      Store s(partial);
      expect(s.get(Table::Records, "old") == "fixed" &&
                 !s.get(Table::Records, "new") &&
                 s.stats().recovered_tail_bytes == 10,
             "restart truncates only the incomplete transaction");
    }
    auto sync = options(root + "/sync");
    {
      Store s(sync);
      s.put(Table::Records, "old", "fixed");
      s.begin();
      s.put(Table::Records, "left", "L");
      s.put(Table::Records, "right", "R");
      fail_sync = true;
      fails([&] { s.commit(); },
            "data sync failure cannot return a durable receipt");
      fail_sync = false;
      s.rollback();
      expect(!s.stats().healthy,
             "failed data synchronization requires a reopen");
    }
    {
      Store s(sync);
      expect(s.get(Table::Records, "old") == "fixed" &&
                 s.get(Table::Records, "left").has_value() ==
                     s.get(Table::Records, "right").has_value(),
             "unacknowledged full transaction recovers atomically");
    }
    auto rename = options(root + "/rename");
    {
      Store s(rename);
      s.put(Table::Records, "one", "1");
      fail_rename = true;
      fails([&] { s.checkpoint(); }, "checkpoint rename failure is visible");
      fail_rename = false;
      expect(s.stats().healthy && s.get(Table::Records, "one") == "1",
             "failure before rename keeps the original journal usable");
      s.put(Table::Records, "two", "2");
    }
    {
      Store s(rename);
      expect(
          s.size(Table::Records) == 2,
          "writes after failed checkpoint recover from the original journal");
    }
    auto directory = options(root + "/directory");
    {
      Store s(directory);
      s.put(Table::Records, "one", "1");
      fail_directory_sync = true;
      fails([&] { s.checkpoint(); },
            "directory synchronization failure is visible");
      fail_directory_sync = false;
      expect(!s.stats().healthy, "failure after checkpoint rename stops future "
                                 "writes to the old inode");
    }
    {
      Store s(directory);
      expect(s.get(Table::Records, "one") == "1",
             "checkpoint selected after reopen contains the committed state");
    }
    std::cout << "CHECKS " << checks << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
