#ifndef SCDN_LOG_PACKET_H
#define SCDN_LOG_PACKET_H
struct scdn_packet_counts {
  unsigned long long tcp_packets, tcp_bytes, tcp_ack, tcp_syn, tcp_syn_ack,
      tcp_syn_only, tcp_fin, tcp_rst;
  unsigned long long udp_packets, udp_bytes;
};
#endif
