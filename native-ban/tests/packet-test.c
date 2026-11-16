#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  int map = bpf_obj_get(argv[1]);
  if (map < 0)
    return 3;
  struct bpf_map_info mi = {0};
  uint32_t size = sizeof(mi);
  if (bpf_obj_get_info_by_fd(map, &mi, &size))
    return 3;
  close(map);
  uint32_t id = 0, next;
  int selected = -1;
  while (!bpf_prog_get_next_id(id, &next)) {
    id = next;
    int fd = bpf_prog_get_fd_by_id(id);
    if (fd < 0)
      continue;
    struct bpf_prog_info info = {0};
    uint32_t maps[64] = {0};
    info.nr_map_ids = 64;
    info.map_ids = (uintptr_t)maps;
    size = sizeof(info);
    if (!bpf_obj_get_info_by_fd(fd, &info, &size) &&
        !strcmp(info.name, "ban_xdp"))
      for (uint32_t i = 0; i < info.nr_map_ids && i < 64; i++)
        if (maps[i] == mi.id)
          selected = fd;
    if (selected == fd)
      break;
    close(fd);
  }
  if (selected < 0)
    return 4;
  unsigned char input[4096], output[8192];
  FILE *f = fopen(argv[2], "rb");
  if (!f)
    return 5;
  size_t length = fread(input, 1, sizeof(input), f);
  fclose(f);
  struct bpf_test_run_opts options = {0};
  options.sz = sizeof(options);
  options.data_in = input;
  options.data_size_in = (uint32_t)length;
  options.data_out = output;
  options.data_size_out = sizeof(output);
  options.repeat = 1;
  int rc = bpf_prog_test_run_opts(selected, &options);
  close(selected);
  if (rc)
    return 6;
  printf("{\"retval\":%u}\n", options.retval);
  return 0;
}
