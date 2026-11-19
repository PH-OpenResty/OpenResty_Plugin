#include "log_sync.hpp"
#include <chrono>
#include <fcntl.h>
#include <sys/file.h>

namespace logs {
struct Service {
  std::string path;
  unsigned interval;
  std::atomic<bool> stop{false};
  std::mutex mutex, wait_mutex;
  std::condition_variable wake;
  scdn_log_sync_status status{};
  std::thread sender, sampler;
  explicit Service(const char *p, unsigned ms) : path(p), interval(ms) {
    sender = std::thread([this] { send_loop(); });
    try {
      sampler = std::thread([this] { sample_loop(); });
    } catch (...) {
      stop.store(true);
      wake.notify_all();
      sender.join();
      throw;
    }
  }
  ~Service() {
    stop.store(true);
    wake.notify_all();
    if (sender.joinable())
      sender.join();
    if (sampler.joinable())
      sampler.join();
  }
  void wait(unsigned ms) {
    std::unique_lock<std::mutex> lock(wait_mutex);
    wake.wait_for(lock, std::chrono::milliseconds(ms),
                  [this] { return stop.load(); });
  }
  void send_loop() {
    std::unique_ptr<Engine> engine;
    Fd election;
    while (!stop.load()) {
      scdn_log_sync_result result{};
      int code = OK;
      try {
        if (!engine) {
          auto conf = config_read(path);
          if (election.value < 0)
            election.value = safe_open(conf.state + "/sender-owner.lock",
                                       O_RDWR | O_CREAT, 0600);
          need(election.value >= 0, IO);
          if (flock(election.value, LOCK_EX | LOCK_NB) < 0) {
            need(errno == EWOULDBLOCK || errno == EAGAIN, IO);
            throw Failure(LOCKED);
          }
          engine = std::make_unique<Engine>(path);
          engine->conf.stop = &stop;
        }
        code = engine->cycle(result);
      } catch (const Failure &e) {
        code = e.code;
      } catch (...) {
        code = STATE;
      }
      if (engine && code != LOCKED &&
          flock(engine->lock.value, LOCK_EX | LOCK_NB) == 0) {
        try {
          auto health = obj();
          put(health, "time_ms",
              uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count()));
          put(health, "success", code == OK ? uint64_t(1) : uint64_t(0));
          put(health, "error", scdn_log_sync_error(code));
          put(health, "pending", result.pending);
          engine->save("sender-health.json", health);
        } catch (...) {
        }
        flock(engine->lock.value, LOCK_UN);
      }
      {
        std::lock_guard<std::mutex> lock(mutex);
        status.running = 1;
        status.cycles++;
        status.error = code;
        status.pending = result.pending;
        status.files = result.files;
        status.confirmed += result.confirmed;
        status.sent_requests += result.sent_requests;
        if (code != OK && code != LOCKED)
          status.failures++;
      }
      wait(code == OK && result.confirmed ? 1 : interval);
    }
    std::lock_guard<std::mutex> lock(mutex);
    status.running = 0;
  }
  void sample_loop() {
    std::unique_ptr<Config> conf;
    while (!stop.load()) {
      try {
        if (!conf)
          conf = std::make_unique<Config>(config_read(path));
        conf->stop = &stop;
        if (!conf->telemetry.enabled)
          return;
        telemetry_cycle(*conf);
      } catch (...) {
        std::lock_guard<std::mutex> lock(mutex);
        status.sample_failures++;
      }
      wait(conf ? conf->telemetry.interval_ms : 1000);
    }
  }
};
} // namespace logs
extern "C" {
void *scdn_log_sync_start(const char *path, unsigned interval) {
  try {
    return new logs::Service(path, interval);
  } catch (...) {
    return nullptr;
  }
}
void scdn_log_sync_stop(void *p) { delete static_cast<logs::Service *>(p); }
void scdn_log_sync_status_read(void *p, scdn_log_sync_status *status) {
  *status = {};
  if (!p)
    return;
  auto *s = static_cast<logs::Service *>(p);
  std::lock_guard<std::mutex> lock(s->mutex);
  *status = s->status;
}
}
