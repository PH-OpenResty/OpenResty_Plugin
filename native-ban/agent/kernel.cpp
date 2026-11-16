#include "ban.hpp"
#include <cstring>
#include <fcntl.h>
#include <linux/magic.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <openssl/rand.h>
namespace ban {
static void ensure_dir(const std::string &path) {
  int fd = safe_open(path, O_RDONLY | O_DIRECTORY);
  require(fd >= 0, "private_directory_missing");
  struct stat st;
  bool ok = !fstat(fd, &st) && st.st_uid == geteuid() && !(st.st_mode & 077);
  close(fd);
  require(ok, "private_directory_permissions");
}
Kernel::Kernel(const Config &c) : pin(c.pin) {
  ensure_dir(pin);
  int dir = safe_open(pin, O_RDONLY | O_DIRECTORY);
  struct statfs fs;
  require(!fstatfs(dir, &fs) && fs.f_type == BPF_FS_MAGIC,
          "pin_directory_not_bpffs");
  close(dir);
  object = bpf_object__open_file(c.object_file.c_str(), nullptr);
  require(object && !libbpf_get_error(object), "bpf_object_open");
  bpf_map *map;
  unsigned reused = 0;
  bool identity_reused = false;
  bpf_object__for_each_map(map, object) {
    auto name = pin + "/" + bpf_map__name(map);
    int existing = bpf_obj_get(name.c_str());
    if (existing >= 0) {
      reused++;
      if (std::string(bpf_map__name(map)) == "identity")
        identity_reused = true;
      bpf_map_info info{};
      uint32_t size = sizeof(info);
      require(!bpf_obj_get_info_by_fd(existing, &info, &size) &&
                  info.type == (uint32_t)bpf_map__type(map) &&
                  info.key_size == bpf_map__key_size(map) &&
                  info.value_size == bpf_map__value_size(map) &&
                  info.max_entries == bpf_map__max_entries(map),
              "pinned_map_mismatch");
      require(!bpf_map__reuse_fd(map, existing), "map_reuse");
      close(existing);
    } else
      require(errno == ENOENT, "pin_read_failed");
  }
  require(!reused || identity_reused, "unowned_existing_pins");
  require(!bpf_object__load(object), "bpf_verifier_or_load_failed");
  {
    int owner = bpf_object__find_map_fd_by_name(object, "identity");
    uint32_t index = 0;
    std::array<uint8_t, 32> actual{}, expected{};
    unsigned size = 0;
    require(owner >= 0 &&
                EVP_Digest(c.immutable.data(), c.immutable.size(),
                           expected.data(), &size, EVP_sha256(),
                           nullptr) == 1 &&
                size == 32,
            "pin_identity_digest");
    require(!bpf_map_lookup_elem(owner, &index, actual.data()),
            "pin_identity_read");
    std::array<uint8_t, 32> zero{};
    if (actual == zero)
      require(!bpf_map_update_elem(owner, &index, expected.data(), BPF_ANY),
              "pin_identity_write");
    else
      require(actual == expected, "pin_identity_conflict");
  }
  bpf_object__for_each_map(map, object) {
    auto name = pin + "/" + bpf_map__name(map);
    if (bpf_map__pin(map, name.c_str()))
      require(errno == EEXIST, "map_pin_failed");
  }
  bans = bpf_object__find_map_fd_by_name(object, "bans");
  int svc = bpf_object__find_map_fd_by_name(object, "services"),
      vips = bpf_object__find_map_fd_by_name(object, "vips");
  require(bans >= 0 && svc >= 0 && vips >= 0, "required_maps");
  uint8_t one = 1;
  for (auto &s : c.services) {
    require(!bpf_map_update_elem(svc, &s, &one, BPF_ANY) &&
                !bpf_map_update_elem(vips, &s.ip, &one, BPF_ANY),
            "service_map_update");
  }
  auto *program = bpf_object__find_program_by_name(
      object, c.mode == "xdp_native" ? "ban_xdp" : "ban_tcx");
  require(program, "program_missing");
  for (auto &interface : c.interfaces) {
    auto linkpath = pin + "/link-" + interface;
    link_paths.push_back(linkpath);
    unsigned index = if_nametoindex(interface.c_str());
    require(index, "interface_missing");
    int existing = bpf_obj_get(linkpath.c_str());
    if (existing >= 0) {
      bpf_link_info info{};
      uint32_t size = sizeof(info);
      require(!bpf_obj_get_info_by_fd(existing, &info, &size), "link_info");
      int previous = bpf_prog_get_fd_by_id(info.prog_id);
      require(previous >= 0, "link_program");
      bpf_prog_info before{}, after{};
      size = sizeof(before);
      require(!bpf_obj_get_info_by_fd(previous, &before, &size),
              "program_info");
      size = sizeof(after);
      require(!bpf_obj_get_info_by_fd(bpf_program__fd(program), &after, &size),
              "program_info");
      close(previous);
      require(!memcmp(before.tag, after.tag, 8),
              "pinned_program_version_requires_maintenance");
      require(
          c.mode == "xdp_native"
              ? (info.type == BPF_LINK_TYPE_XDP && info.xdp.ifindex == index)
              : (info.type == BPF_LINK_TYPE_TCX && info.tcx.ifindex == index),
          "pinned_link_scope_mismatch");
      pinned_links.push_back(existing);
      continue;
    }
    require(errno == ENOENT, "link_pin_read");
    bpf_link *link = nullptr;
    if (c.mode == "xdp_native")
      link = bpf_program__attach_xdp(program, (int)index);
    else {
      bpf_tcx_opts opts{};
      opts.sz = sizeof(opts);
      opts.flags = BPF_F_BEFORE;
      link = bpf_program__attach_tcx(program, (int)index, &opts);
    }
    require(link && !libbpf_get_error(link),
            "attach_failed_existing_program_or_capability");
    links.push_back(link);
    require(!bpf_link__pin(link, linkpath.c_str()), "link_pin");
  }
  ready = true;
}
Kernel::~Kernel() {
  for (auto *l : links)
    bpf_link__destroy(l);
  for (int fd : pinned_links)
    close(fd);
  if (object)
    bpf_object__close(object);
}
void Kernel::put(const ban_address &a, const ban_kernel_value &v) {
  require(ready && !bpf_map_update_elem(bans, &a, &v, BPF_ANY),
          "kernel_ban_update");
  ban_kernel_value read{};
  require(!bpf_map_lookup_elem(bans, &a, &read) &&
              !memcmp(&read, &v, sizeof(v)),
          "kernel_ban_verify");
}
void Kernel::remove(const ban_address &a) {
  if (bpf_map_delete_elem(bans, &a))
    require(errno == ENOENT, "kernel_ban_delete");
}
uint64_t Kernel::watermark() {
  int fd = bpf_object__find_map_fd_by_name(object, "checkpoint");
  uint32_t key = 0;
  uint64_t value = 0;
  require(fd >= 0 && !bpf_map_lookup_elem(fd, &key, &value),
          "kernel_checkpoint_read");
  return value;
}
void Kernel::watermark(uint64_t value) {
  int fd = bpf_object__find_map_fd_by_name(object, "checkpoint");
  uint32_t key = 0;
  require(fd >= 0 && !bpf_map_update_elem(fd, &key, &value, BPF_ANY),
          "kernel_checkpoint_write");
}
std::map<std::string, ban_kernel_value> Kernel::entries() {
  std::map<std::string, ban_kernel_value> out;
  ban_address current{}, next{};
  bool first = true;
  unsigned budget = 0;
  while (!bpf_map_get_next_key(bans, first ? nullptr : &current, &next)) {
    first = false;
    current = next;
    require(++budget <= BAN_CAPACITY, "kernel_map_iteration");
    ban_kernel_value v{};
    if (!bpf_map_lookup_elem(bans, &next, &v))
      out[ip_text(next)] = v;
  }
  require(errno == ENOENT, "kernel_map_read");
  return out;
}
void Kernel::detach() {
  for (auto *l : links) {
    bpf_link__unpin(l);
    bpf_link__detach(l);
  }
  for (int fd : pinned_links)
    bpf_link_detach(fd);
  for (const auto &path : link_paths)
    if (unlink(path.c_str()))
      require(errno == ENOENT, "owned_link_unpin_failed");
}
View::View(const Config &c) {
  fd = safe_open(c.view_file, O_RDWR | O_CREAT, 0600);
  require(fd >= 0, "view_open");
  struct stat st;
  struct statfs fs;
  require(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
              !(st.st_mode & 077) && st.st_nlink == 1,
          "view_permissions");
  require(!fstatfs(fd, &fs) && fs.f_type == TMPFS_MAGIC, "view_requires_tmpfs");
  bool fresh = st.st_size == 0;
  if (fresh)
    require(!ftruncate(fd, sizeof(ban_view)), "view_allocate");
  else
    require(st.st_size == sizeof(ban_view), "view_layout_size");
  data = (ban_view *)mmap(nullptr, sizeof(ban_view), PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);
  require(data != MAP_FAILED, "view_map");
  uint8_t boot[16];
  require(ban_uuid(c.boot.c_str(), boot), "boot_id");
  if (fresh) {
    memset(data, 0, sizeof(*data));
    data->magic = BAN_VIEW_MAGIC;
    data->version = BAN_VERSION;
    data->slots = BAN_SLOTS;
    memcpy(data->boot, boot, 16);
    require(RAND_bytes(data->hash_key,16)==1,"view_hash_seed");
  } else
    require(ban_view_valid(data, sizeof(*data), boot),
            "view_boot_or_layout_mismatch");
  readonly = safe_open(c.view_file, O_RDONLY);
  require(readonly >= 0, "view_readonly_open");
}
View::~View() {
  if (data && data != MAP_FAILED)
    munmap(data, sizeof(*data));
  if (fd >= 0)
    close(fd);
  if (readonly >= 0)
    close(readonly);
}
void View::publish(const ban_record &r, bool remove) {
  ban_record current{};
  int found=ban_view_lookup(data,&r.ip,r.scope,0,&current);
  if(!remove&&found==1&&!memcmp(&current,&r,sizeof(r)))return;
  if(remove&&found==0)return;
  require(ban_view_write(data, &r, remove), "view_capacity_or_unstable");
}
} // namespace ban
