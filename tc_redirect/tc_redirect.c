//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP    0x0800

#define IP_P_TCP    6
#define IP_P_UDP    17

#define ETH_SIZE    sizeof(struct ethhdr)
#define IP_SIZE	    sizeof(struct iphdr)
#define UDP_SIZE    sizeof(struct udphdr)
#define TCP_SIZE    sizeof(struct tcphdr)

#define MAX_ENTRIES_PER_PACKET 20

char __license[] SEC("license") = "Dual MIT/GPL";

struct hdr {
	struct ethhdr* eth;
	struct iphdr* ip;
	struct udphdr* udp;
};

static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end);


static __always_inline struct hdr try_parse_udp(void* data, void* data_end);

#define SERVER_COUNT 1

__u16 redirect_port = 12345;
__u16 server_ports[SERVER_COUNT] = {
	12346,
	12347,
	12348,
};
//192.168.50.224
__u32 server_ips[SERVER_COUNT]={
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
};

__u8 server_macs[SERVER_COUNT][6] = {
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
};


SEC("tc")
int tcdump(struct __sk_buff *ctx) {
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	struct hdr header = try_parse_udp(data, data_end);

	if (header.udp == NULL) {
		return TC_ACT_OK;
	}
	if(header.udp->dest != bpf_htons(redirect_port)){
		return TC_ACT_OK;
	}

	int ret;
	for (int i=0;i<SERVER_COUNT;i++){
		uint16_t new_port = bpf_htons(server_ports[i]);
		ret = bpf_skb_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_port, sizeof(new_port), 0);
		bpf_printk("replace port %d", ret);

		uint32_t new_daddr = bpf_htonl(server_ips[i]);
		ret	= bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_daddr,
				sizeof(u32), 0);
		bpf_printk("replace ip %d", ret);

		Elf32_Half check = 0;
		bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
			sizeof(u16), 0);
		header = try_parse_udp((void*) ctx->data ,(void*) ctx->data_end);
		if (header.udp != NULL)
			check = compute_ip_checksum(header.ip, (void*) ctx->data_end);
		bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
			sizeof(u16), 0);

		ret = bpf_skb_store_bytes(ctx, 0, server_macs[i], 6, 0);
		bpf_printk("replace mac %d", ret);

		ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
		bpf_printk("clone redirect %d", ret);

		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}





static __always_inline struct hdr try_parse_udp(void* data, void* data_end){
	if(data + ETH_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct ethhdr* eth = data;
	if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return (struct hdr) {NULL,NULL, NULL};

	if(data + ETH_SIZE + IP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct iphdr* ip = data + ETH_SIZE;
	if(ip->protocol != IP_P_UDP){
		return (struct hdr) {NULL,NULL, NULL};
	}
	
	if(data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct udphdr* udp = data + ETH_SIZE + IP_SIZE;

	

	return (struct hdr){eth,ip, udp};
}




static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end) {
    __u16 *next_ip_u16 = (__u16 *)ip;
    __u16 *end = (__u16 *)data_end;
    __u32 csum = 0;

    // Ensure that `ip` is valid and does not cross data_end
    if ((void *)next_ip_u16 + sizeof(*ip) > data_end) {
        return 0; // Invalid access, return 0
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}
