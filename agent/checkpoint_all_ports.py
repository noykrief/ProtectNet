from bcc import BPF

# Load BPF program
bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>

int packet_filter(struct __sk_buff *skb) {
    // Load Ethernet header
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return 0;
    }

    // Filter only IP packets
    if (eth.h_proto != htons(ETH_P_IP)) {
        return 0;
    }

    // Load IP header
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0) {
        return 0;
    }

    // Filter only TCP packets
    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    // Calculate the offset of the TCP header
    int ip_header_len = ip.ihl * 4;
    int tcp_header_offset = sizeof(eth) + ip_header_len;

    // Load TCP header
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, tcp_header_offset, &tcp, sizeof(tcp)) < 0) {
        return 0;
    }

    // Exclude SSH
    if (tcp.dest == htons(22) || tcp.source == htons(22)) {
        return 0;
    }

    // Filter packets
    bpf_trace_printk("Packet detected: src_port=%d, dst_port=%d\\n", ntohs(tcp.source), ntohs(tcp.dest));

    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
fn = b.load_func("packet_filter", BPF.SOCKET_FILTER)

# Attach BPF program to network interface
BPF.attach_raw_socket(fn, "ens160")

print("Tracing packets... Press Ctrl+C to exit.")
try:
    b.trace_print()
except KeyboardInterrupt:
    pass