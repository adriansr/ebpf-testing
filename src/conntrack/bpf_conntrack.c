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

#include "bpf_elf.h"
#include "bpf_funcs.h"
#include "shared.h"

#define TRACE_PRINTK(FMT, ARGS...) do { \
                char fmt[] = FMT; \
                bpf_trace_printk(fmt, sizeof(fmt), ## ARGS); \
            } while(0)

#define SWAP(A,B) do { \
        typeof((A)) tmp = (A); \
        (A) = (B); \
        (B) = tmp; \
    } while(0)

struct bpf_elf_map __section(ELF_SECTION_MAPS) map_conf = {
    .type           =       BPF_MAP_TYPE_ARRAY,
    .id             =       34, //BPF_MAP_ID_CONF,
    .size_key       =       sizeof(uint32_t),
    .size_value     =       sizeof(struct conntrack_conf_t),
    .max_elem       =       1, /* only one conf entry */
    .pinning = 2
};

#if 0
struct bpf_elf_map __section(ELF_SECTION_MAPS) map_ct = {
    .type           =       BPF_MAP_TYPE_HASH,
//.id             =       BPF_MAP_ID_CT,
    .size_key       =       sizeof(struct conntrack_key_t),
    .size_value     =       sizeof(struct conntrack_value_t),
    .max_elem       =       512, /* TODO */
    .pinning = 2
};
#endif

struct conntrack_conf_t* __attribute__((always_inline)) get_conf() {
    uint32_t key = 0;
    return bpf_map_lookup_elem(&map_conf, &key);
}

__section("filter-in")
int handle_ingress(struct __sk_buff *skb)
{
    struct conntrack_conf_t *conf = get_conf();
    /* seems that a map of type ARRAY is initialised with zeroed memory
     */
    if (conf == 0 || !conf->valid) {
        /* not yet configured */
        TRACE_PRINTK("MIDO: *NOT* configured (ingress)");
        return 0;
    }
    
    const int ip_offset = BPF_LL_OFF + ETH_HLEN;

    char ip_proto, ip_len;
    uint16_t frag_off;
    struct conntrack_key_t key = {0};

    int l4_offset;
    
    // check for IPv4 protocol in eth_type field
    if (skb->protocol != htons(ETH_P_IP))
        return 0;

    // check for IP version 4 in IP header
    ip_len = load_byte(skb, ip_offset);
    if ((ip_len & 0xf0) != 0x40)
        return 0;

    ip_len = (ip_len & 0xf) << 2;

    frag_off     = load_half(skb, ip_offset + offsetof(struct iphdr, frag_off));
    ip_proto     = load_byte(skb, ip_offset + offsetof(struct iphdr, protocol));
    // WARN: dst and src swapped to build reverse key
    key.dst_addr = load_word(skb, ip_offset + offsetof(struct iphdr, saddr));
    key.src_addr = load_word(skb, ip_offset + offsetof(struct iphdr, daddr));

    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
        return 0;
    }
    
    // TODO(adrian): support fragments?
    if ( (frag_off & 0x3fff) != 0) {
        return 0;
    }

    // TCP and UDP have ports at same location
    l4_offset    = ip_offset + ip_len;
    // WARN: dst and src swapped to build reverse key
    key.dst_port = load_half(skb, l4_offset + 0);
    key.src_port = load_half(skb, l4_offset + 2);
    key.protocol = ip_proto;

    uint64_t now = bpf_ktime_get_ns();

    TRACE_PRINTK("MIDO: Ingress from: %x:%u\n", key.src_addr, key.src_port);
    TRACE_PRINTK("MIDO:           to: %x:%u\n", key.dst_addr, key.dst_port);
    TRACE_PRINTK("MIDO:        proto: %d\n", key.protocol);
#if 0   
    struct conntrack_value_t *value = bpf_map_lookup_elem(&map_ct, &key);
    
    // TODO: actual expiration of values
    if (value!=0 /*&& (now - value->last_seen) < conf->expiration_ns*/) {
        return 0;
    }

    TRACE_PRINTK("MIDO: Dropped packet from: %x:%u\n", key.src_addr, key.src_port);
    TRACE_PRINTK("MIDO:                  to: %x:%u\n", key.dst_addr, key.dst_port);
#endif
    return TC_ACT_SHOT;
}

__section("filter-out")
int handle_egress(struct __sk_buff *skb)
{
    struct conntrack_conf_t *conf = get_conf();
    /* seems that a map of type ARRAY is initialised with zeroed memory
     */
    if (conf == 0 || !conf->valid) {
        /* not yet configured */
        TRACE_PRINTK("MIDO: *NOT* configured (egress)");
        return 0;
    }
    
    const int ip_offset = BPF_LL_OFF + ETH_HLEN;

    char ip_proto, ip_len;
    uint16_t frag_off;
    struct conntrack_key_t key = {0};

    int l4_offset;
    
    // check for IPv4 protocol in eth_type field
    if (skb->protocol != htons(ETH_P_IP))
        return 0;

    // check for IP version 4 in IP header
    ip_len = load_byte(skb, ip_offset);
    if ((ip_len & 0xf0) != 0x40)
        return 0;

    ip_len = (ip_len & 0xf) << 2;

    frag_off     = load_half(skb, ip_offset + offsetof(struct iphdr, frag_off));
    ip_proto     = load_byte(skb, ip_offset + offsetof(struct iphdr, protocol));
    key.src_addr = load_word(skb, ip_offset + offsetof(struct iphdr, saddr));
    key.dst_addr = load_word(skb, ip_offset + offsetof(struct iphdr, daddr));

    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
        return 0;
    }
    
    // TODO(adrian): support fragments?
    if ( (frag_off & 0x3fff) != 0) {
        return 0;
    }

    // TCP and UDP have ports at same location
    l4_offset    = ip_offset + ip_len;
    key.src_port = load_half(skb, l4_offset + 0);
    key.dst_port = load_half(skb, l4_offset + 2);
    key.protocol = ip_proto;

    uint64_t now = bpf_ktime_get_ns();

    TRACE_PRINTK("MIDO: Egress from: %x:%u\n", key.src_addr, key.src_port);
    TRACE_PRINTK("MIDO:          to: %x:%u\n", key.dst_addr, key.dst_port);
    TRACE_PRINTK("MIDO:       proto: %d\n", key.protocol);
#if 0
    if (1/*key.src_addr == conf->source_address*/) {
        struct conntrack_value_t value = {0};
        value.last_seen = now;
        bpf_map_update_elem(&map_ct, &key, &value, 0);
        TRACE_PRINTK("MIDO: Allowing from: %x:%u\n", key.src_addr, key.src_port);
        TRACE_PRINTK("MIDO:            to: %x:%u\n", key.dst_addr, key.dst_port);
        return 0;
    }
#endif
    return TC_ACT_SHOT;
}

char _license[] __section(ELF_SECTION_LICENSE) = "GPL";
