#include "log_sync.hpp"
#include <chrono>
#include <csignal>
#include <iostream>
static volatile sig_atomic_t done;
static void stop(int) { done = 1; }
int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: scdn-log-sync --check|--once|--sample|--run "
                 "/absolute/config.json\n";
    return 2;
  }
  try {
    std::string mode = argv[1];
    if (mode == "--check") {
      logs::config_read(argv[2]);
      std::cout << "configuration valid\n";
      return 0;
    }
    if (mode == "--sample") {
      auto c = logs::config_read(argv[2]);
      std::cout << logs::dump(logs::sample(c, {})) << "\n";
      return 0;
    }
    if (mode == "--once") {
      logs::Engine engine(argv[2]);
      scdn_log_sync_result result{};
      int rc = engine.cycle(result);
      std::cout << "{\"confirmed\":" << result.confirmed
                << ",\"pending\":" << result.pending << ",\"error\":\""
                << scdn_log_sync_error(rc) << "\"}\n";
      return rc;
    }
    if (mode == "--run") {
      std::signal(SIGTERM, stop);
      std::signal(SIGINT, stop);
      void *service = scdn_log_sync_start(argv[2], 250);
      logs::need(service != nullptr, logs::STATE);
      while (!done)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      scdn_log_sync_stop(service);
      return 0;
    }
  } catch (const logs::Failure &e) {
    std::cerr << scdn_log_sync_error(e.code) << "\n";
    return e.code;
  } catch (...) {
    std::cerr << "internal\n";
    return 3;
  }
  return 2;
}
