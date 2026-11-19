#include "packet.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, u16);
  __type(value, u8);
} ports SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, u32);
  __type(value, struct scdn_packet_counts);
} packets SEC(".maps");
static __always_inline u16 word(u8 *p) { return ((u16)p[0] << 8) | p[1]; }
static __always_inline long load(struct __sk_buff *skb,u32 offset,void *out,u32 size){
  return bpf_skb_load_bytes_relative(skb,offset,out,size,BPF_HDR_START_NET);
}
SEC("socket") int count_packets(struct __sk_buff *skb) {
  u8 ip[40], transport[20];
  u32 offset = 0, direction = skb->pkt_type == 4 ? 1 : 0;
  u16 type = __builtin_bswap16((u16)skb->protocol);
#pragma unroll
  for (int i = 0; i < 2; i++)
    if (type == 0x8100 || type == 0x88a8) {
      u8 vlan[4];
      if (load(skb, offset, vlan, 4))
        return 0;
      type = word(vlan + 2);
      offset += 4;
    }
  u8 next = 0;
  if (type == 0x0800) {
    if (load(skb, offset, ip, 20) || ip[0] >> 4 != 4 ||
        (ip[0] & 15) < 5)
      return 0;
    if (word(ip + 6) & 0x1fff)
      return 0;
    next = ip[9];
    offset += (ip[0] & 15) * 4;
  } else if (type == 0x86dd) {
    if (load(skb, offset, ip, 40) || ip[0] >> 4 != 6)
      return 0;
    next = ip[6];
    offset += 40;
#pragma unroll
    for (int i = 0; i < 6; i++) {
      if (next == 0 || next == 43 || next == 60) {
        u8 extension[2];
        if (load(skb, offset, extension, 2))
          return 0;
        next = extension[0];
        offset += ((u32)extension[1] + 1) * 8;
      } else if (next == 44) {
        u8 fragment[8];
        if (load(skb, offset, fragment, 8) ||
            word(fragment + 2) & 0xfff8)
          return 0;
        next = fragment[0];
        offset += 8;
      }
    }
  } else
    return 0;
  if (next != 6 && next != 17)
    return 0;
  if (load(skb, offset, transport, next == 6 ? 20 : 8))
    return 0;
  u16 port = word(transport + (direction ? 0 : 2));
  if (!bpf_map_lookup_elem(&ports, &port))
    return 0;
  struct scdn_packet_counts *counts = bpf_map_lookup_elem(&packets, &direction);
  if (!counts)
    return 0;
  if (next == 17) {
    counts->udp_packets++;
    counts->udp_bytes += skb->len;
    return 0;
  }
  if ((transport[12] >> 4) < 5)
    return 0;
  counts->tcp_packets++;
  counts->tcp_bytes += skb->len;
  u8 flags = transport[13];
  if (flags & 16)
    counts->tcp_ack++;
  if (flags & 2)
    counts->tcp_syn++;
  if ((flags & 18) == 18)
    counts->tcp_syn_ack++;
  if ((flags & 18) == 2)
    counts->tcp_syn_only++;
  if (flags & 1)
    counts->tcp_fin++;
  if (flags & 4)
    counts->tcp_rst++;
  /* Zero only discards this AF_PACKET capture copy; no TC/XDP hook is used. */
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
