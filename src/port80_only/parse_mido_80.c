#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "bpf_funcs.h"

#define TRACE_PRINTK(FMT, ARGS...) do { \
                char fmt[] = FMT; \
                bpf_trace_printk(fmt, sizeof(fmt), ## ARGS); \
            } while(0)

__section("classifier")
int handle_ingress(struct __sk_buff *skb)
{
    const uint16_t allowed_port = 80;

    const int ip_offset = BPF_LL_OFF + ETH_HLEN;

    char ip_proto, ip_len;
    uint16_t frag_off;
    struct {
        uint32_t address;
        uint16_t port;
    } src, dst;

    int tcp_offset;

    if (skb->protocol != htons(ETH_P_IP))
        return 0;

    ip_len = load_byte(skb, ip_offset);
    if ((ip_len & 0xf0) != 0x40)
        return 0;

    ip_len = (ip_len & 0xf) << 2;

    frag_off    = load_half(skb, ip_offset + offsetof(struct iphdr, frag_off));
    ip_proto    = load_byte(skb, ip_offset + offsetof(struct iphdr, protocol));
    src.address = load_word(skb, ip_offset + offsetof(struct iphdr, saddr));
    dst.address = load_word(skb, ip_offset + offsetof(struct iphdr, daddr));

    //char line0[] = "MIDO: len:%u off:%u";
    //bpf_trace_printk(line0, sizeof(line0), ip_len, ip_offset);

    if (ip_proto != IPPROTO_TCP) {
        return 0;
    }
    
    // TODO(adrian): support fragments?
    if ( (frag_off & 0x3fff) != 0) {
        return 0;
    }

    tcp_offset = ip_offset + ip_len;

    src.port    = load_half(skb, tcp_offset + offsetof(struct tcphdr, source));
    dst.port    = load_half(skb, tcp_offset + offsetof(struct tcphdr, dest));

    if (dst.port == allowed_port || src.port == allowed_port)
        return 0;

    TRACE_PRINTK("MIDO: Dropped packet from: %x:%u\n", src.address, src.port);
    TRACE_PRINTK("MIDO:                  to: %x:%u\n", dst.address, dst.port);

    return TC_ACT_SHOT;
}

char _license[] __section("license") = "GPL";
