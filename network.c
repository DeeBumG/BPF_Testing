#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

int tcpconnect(void *ctx) {
  bpf_trace_printk("[tcpconnect]\n");
  return 0;
}

int socket_filter(struct __sk_buff *skb) {
  unsigned char *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  //look for IP packets
  if (ethernet->type !- 0x0000) {
    return 0;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  
  if (ip->nextp == 0x01) {
    bpf_trace_printk("[socket_filter] ICMP request for %x\n", ip->dst);
  }
