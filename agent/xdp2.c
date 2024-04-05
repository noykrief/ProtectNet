#include <stdint.h>
#include <linux/types.h>     // for __u8, __sum16
#include <linux/if_ether.h> // for struct ethhdr
#include <linux/ip.h>       // for struct iphdr

struct icmphdr_common
{
    __u8 type;
    __u8 code;
    __sum16 cksum;
};

static inline int parse_eth(void *data, u64 nh_off, void *data_end)
{
    // Check if data + nh_off exceeds data_end (potential buffer overflow)
    if ((void *)(data + nh_off) > data_end) {
        return -1; // Indicate error
    }

    struct ethhdr *eth = data + nh_off;

    // Check if exceeding buffer end after accessing eth[1]
    if ((void *)&eth[1] > data_end) {
        return -1; // Indicate error
    }
    return eth->h_proto;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
    // Check for buffer overflow
    if ((void *)(data + nh_off) > data_end) {
        return -1; // Indicate error
    }

    struct iphdr *iph = data + nh_off;

    // Check if exceeding buffer end after accessing iph[1]
    if ((void *)&iph[1] > data_end) {
        return -1; // Indicate error
    }
    return iph->protocol;
}

// Example usage (assuming you have a packet data buffer)
int main() {
    void* packet_data; // Replace with your actual packet data
    u64 offset = 0; // Adjust offset based on your packet structure

    int eth_proto = parse_eth(packet_data, offset, packet_data + sizeof(packet_data));
    if (eth_proto < 0) {
        // Handle parse_eth error
        return -1;
    }

    if (eth_proto == ETH_P_IP) {
        int ip_proto = parse_ipv4(packet_data, offset + sizeof(struct ethhdr), packet_data + sizeof(packet_data));
        if (ip_proto < 0) {
            // Handle parse_ipv4 error
            return -1;
        }
        // Handle specific IP protocol (e.g., ICMP) based on ip_proto
    }

    return 0;
}