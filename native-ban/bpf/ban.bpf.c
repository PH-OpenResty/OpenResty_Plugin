#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned long long u64;
struct address {
  u32 family;
  u8 bytes[16];
};
struct service {
  struct address ip;
  u16 port;
  u8 protocol, reserved;
};
struct value {
  u64 deadline;
  u8 id[16];
  u64 generation;
};
struct identity_value {
  u8 digest[32];
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct identity_value);
} identity SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64);
} checkpoint SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct address);
  __type(value, struct value);
} bans SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct service);
  __type(value, u8);
} services SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, struct address);
  __type(value, u8);
} vips SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, u32);
  __type(value, u64);
} counters SEC(".maps");
static __always_inline int decide(void *data, void *end) {
  u8 *p = data;
  u16 proto;
  struct address src = {}, dst = {};
  struct service key = {};
  u32 offset = 14;
  u8 next = 0;
  int fragment = 0;
  if (p + 14 > (u8 *)end)
    return 0;
  proto = ((u16)p[12] << 8) | p[13];
#pragma unroll
  for (int i = 0; i < 2; i++) {
    if (proto == 0x8100 || proto == 0x88a8) {
      if (p + offset + 4 > (u8 *)end)
        return 0;
      proto = ((u16)p[offset + 2] << 8) | p[offset + 3];
      offset += 4;
    }
  }
  if (proto == 0x0800) {
    if (p + offset + 20 > (u8 *)end)
      return 0;
    u8 *ip = p + offset;
    u32 ihl = (ip[0] & 15) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || p + offset + ihl > (u8 *)end)
      return 0;
    src.family = dst.family = 4;
    __builtin_memcpy(src.bytes + 12, ip + 12, 4);
    __builtin_memcpy(dst.bytes + 12, ip + 16, 4);
    next = ip[9];
    fragment = (((u16)ip[6] << 8) | ip[7]) & 0x3fff;
    offset += ihl;
  } else if (proto == 0x86dd) {
    if (p + offset + 40 > (u8 *)end)
      return 0;
    u8 *ip = p + offset;
    if ((ip[0] >> 4) != 6)
      return 0;
    src.family = dst.family = 6;
    __builtin_memcpy(src.bytes, ip + 8, 16);
    __builtin_memcpy(dst.bytes, ip + 24, 16);
    next = ip[6];
    offset += 40;
#pragma unroll
    for (int i = 0; i < 6; i++) {
      if (next == 0 || next == 43 || next == 60) {
        if (p + offset + 2 > (u8 *)end) {
          fragment = 1;
          break;
        }
        u8 *extension = p + offset;
        if (extension + 2 > (u8 *)end)
          return 0;
        u32 size = ((u32)extension[1] + 1) * 8;
        next = extension[0];
        offset += size;
        if (p + offset > (u8 *)end) {
          fragment = 1;
          break;
        }
      } else if (next == 44) {
        fragment = 1;
        break;
      } else
        break;
    }
    if (next == 0 || next == 43 || next == 60 || next == 50 || next == 51)
      fragment = 1;
  } else
    return 0;
  if (!bpf_map_lookup_elem(&vips, &dst))
    return 0;
  struct value *v = bpf_map_lookup_elem(&bans, &src);
  if (!v)
    return 0;
  if (v->deadline <= bpf_ktime_get_boot_ns())
    return 0;
  if (!fragment) {
    if (next != 6 && next != 17)
      return 0;
    if (p + offset + 4 > (u8 *)end)
      return 0;
    key.ip = dst;
    key.protocol = next;
    __builtin_memcpy(&key.port, p + offset + 2, 2);
    if (!bpf_map_lookup_elem(&services, &key))
      return 0;
  }
  u32 index = 0;
  u64 *c = bpf_map_lookup_elem(&counters, &index);
  if (c)
    (*c)++;
  return 1;
}
SEC("xdp") int ban_xdp(struct xdp_md *ctx) {
  return decide((void *)(long)ctx->data, (void *)(long)ctx->data_end)
             ? XDP_DROP
             : XDP_PASS;
}
SEC("tcx/ingress") int ban_tcx(struct __sk_buff *ctx) {
  return decide((void *)(long)ctx->data, (void *)(long)ctx->data_end) ? 2 : -1;
}
char LICENSE[] SEC("license") = "GPL";
