#include <linux/types.h>     // for __u8, __sum16, u64
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
    struct ethhdr *eth = data + nh_off;

    if ((void *)&eth[1] > data_end)
        return 0;
    return eth->h_proto;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;

    if ((void *)&iph[1] > data_end)
        return 0;
    return iph->protocol;   
}