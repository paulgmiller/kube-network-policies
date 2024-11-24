#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

enum verdict {
    ALLOW = 1,
    BLOCK = 0,
};

// Shared map for userspace to communicate verdicts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(enum verdict));
    __uint(max_entries, 1024); // Limit the number of tracked flows
} flow_verdict_map SEC(".maps");

// Perf event map for sending flow info to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} perf_event_map SEC(".maps");

// Helper to generate a flow key
static __inline void get_flow_key(struct flow_key *key, struct iphdr *ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = protocol;
}

// XDP program
SEC("xdp")
int handle_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        src_port = tcp->source;
        dst_port = tcp->dest;

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    // Populate flow key
    get_flow_key(&key, ip, src_port, dst_port, ip->protocol);

    // Check the map for a verdict
    enum verdict *v = bpf_map_lookup_elem(&flow
