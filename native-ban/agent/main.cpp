#include "ban.hpp"
#include <curl/curl.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
static std::atomic<bool> stop{false};
static std::atomic<bool> reload_policy{false};
static void signal_stop(int) { stop = true; }
static void signal_reload(int) { reload_policy = true; }
int main(int argc, char **argv) {
  int lock = -1, runtime_lock=-1;
  try {
    ban::require(argc == 3 || argc == 4,
                 "usage: scdn-ban-agent --config /absolute/policy.json "
                 "[--check|--detach]");
    ban::require(std::string(argv[1]) == "--config", "config_argument");
    umask(0077);
    auto conf = ban::config_read(argv[2]);
    ban::require(geteuid() != conf.worker_uid && geteuid() != conf.sync_uid,
                 "agent_worker_uid_separation");
    ban::require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK,
                 "curl_init");
    auto offsets = ban::read_file(
        "/proc/" + std::to_string(getpid()) + "/timens_offsets", 4096);
    std::istringstream offset_stream(offsets);
    std::string clock;
    long long seconds, nanos;
    bool found = false;
    while (offset_stream >> clock >> seconds >> nanos) {
      if (clock == "boottime") {
        found = true;
        ban::require(seconds == 0 && nanos == 0, "boottime_namespace_offset");
      }
    }
    ban::require(found, "time_namespace_unavailable");
    if (argc == 4 && std::string(argv[3]) == "--check") {
      std::cout
          << "Ban configuration valid; runtime enforcement not started.\n";
      return 0;
    }
    for (const auto &path : {conf.state, conf.runtime}) {
      int directory = ban::safe_open(path, O_RDONLY | O_DIRECTORY);
      ban::require(directory >= 0, "state_or_runtime_directory_missing");
      struct stat st{};
      bool ok = !fstat(directory, &st) && st.st_uid == geteuid() &&
                !(st.st_mode & (path == conf.state ? 077 : 027));
      close(directory);
      ban::require(ok, "state_or_runtime_directory_permissions");
    }
    lock = ban::safe_open(conf.state + "/agent.lock", O_RDWR | O_CREAT, 0600);
    ban::require(lock >= 0 && !flock(lock, LOCK_EX | LOCK_NB),
                 "agent_already_running");
    runtime_lock=ban::safe_open(conf.runtime+"/agent.lock",O_RDWR|O_CREAT,0600);
    ban::require(runtime_lock>=0&&!flock(runtime_lock,LOCK_EX|LOCK_NB),"runtime_already_owned");
    ban::Engine engine(conf);
    if (argc == 4) {
      ban::require(std::string(argv[3]) == "--detach", "unknown_argument");
      engine.kernel->detach();
      std::cout << "Owned BPF links detached.\n";
      return 0;
    }
    signal(SIGTERM, signal_stop);
    signal(SIGINT, signal_stop);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, signal_reload);
    ban::serve(engine, stop, reload_policy, argv[2]);
    close(lock);
    close(runtime_lock);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "scdn-ban-agent: " << e.what() << "\n";
    if (lock >= 0)
      close(lock);
    if(runtime_lock>=0)close(runtime_lock);
    return 1;
  }
}
