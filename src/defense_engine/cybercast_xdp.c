// CyberCast AI - Line-Rate eBPF / XDP Network State Probe
// Compiles with: clang -O2 -target bpf -c cybercast_xdp.c -o cybercast_xdp.o
// Loads with: ip link set dev eth0 xdpgeneric obj cybercast_xdp.o sec xdp

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct telemetry_state {
    __u64 total_bytes;
    __u64 total_packets;
    __u32 syn_flags;
    __u32 ack_flags;
    __u32 rst_flags;
    __u32 fin_flags;
    __u32 last_ttl;
    __u32 min_window;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct telemetry_state);
} state_map SEC(".maps");

SEC("xdp")
int cybercast_telemetry_collector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    struct telemetry_state *state = bpf_map_lookup_elem(&state_map, &key);
    if (!state)
        return XDP_PASS;

    // Line-rate atomic header updates (100 Gbps line-rate zero copy)
    __sync_fetch_and_add(&state->total_packets, 1);
    __sync_fetch_and_add(&state->total_bytes, (__u64)(data_end - data));
    state->last_ttl = ip->ttl;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->syn) __sync_fetch_and_add(&state->syn_flags, 1);
            if (tcp->ack) __sync_fetch_and_add(&state->ack_flags, 1);
            if (tcp->rst) __sync_fetch_and_add(&state->rst_flags, 1);
            if (tcp->fin) __sync_fetch_and_add(&state->fin_flags, 1);
        }
    }

    return XDP_PASS; // Zero-copy pass-through
}

char _license[] SEC("license") = "GPL";
