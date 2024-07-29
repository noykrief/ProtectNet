#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>

struct key_t {
    __be32 src_ip;
    __be16 dst_port;
};

struct event_t {
    __be32 src_ip;
    __be16 dst_port;
    u64 count;
};

BPF_HASH(packet_count, struct key_t, u64);
BPF_PERF_OUTPUT(events);

int packet_filter(struct __sk_buff *skb) {
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return 0;
    }

    if (eth.h_proto != htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0) {
        return 0;
    }

    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    int ip_header_len = ip.ihl * 4;
    int tcp_header_offset = sizeof(eth) + ip_header_len;

    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, tcp_header_offset, &tcp, sizeof(tcp)) < 0) {
        return 0;
    }

    if (tcp.dest == htons(22) || tcp.source == htons(22)) {
        return 0;
    }

    struct key_t key = {};
    key.src_ip = ip.saddr;
    key.dst_port = tcp.dest;

    u64 *value = packet_count.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 count = 1;
        packet_count.update(&key, &count);
    }

    value = packet_count.lookup(&key);
    if (value && *value > 10) {
        struct event_t event = {
            .src_ip = ip.daddr,
            .dst_port = key.dst_port,
            .count = *value,
        };
        events.perf_submit(skb, &event, sizeof(event));
    }

    return 0;
}
