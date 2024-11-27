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

__u16 src_port[3] = {12346, 12347, 12348};

__u16 ack_port = 12345;
__u32 ack_ip = (192 << 24) | (168 << 16) | (50 << 8) | 213;
__u8 ack_mac[6] = {0x9c, 0x2d, 0xcd, 0x48, 0xb1, 0x04};

SEC("xdp")
int xdp_ack(struct xdp_md *ctx) {
	return XDP_PASS;
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	struct hdr header = try_parse_udp(data, data_end);

	if (header.udp == NULL) {
		return XDP_PASS;
	}
	bool is_target = false;
	for (int i=0;i<3;i++){
		if(header.udp->dest == bpf_htons(src_port[i])){
			is_target = true;
			break;
		}
	}
	if(is_target){
		is_target = header.ip->saddr == bpf_htonl(ack_ip);
		bpf_printk("is_target %d", is_target);
	}
	if(!is_target){
		return XDP_PASS;
	}


	int ret;
	uint16_t new_src_port = header.udp->dest;
	uint16_t new_dst_port = bpf_htons(ack_port);
	ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_dst_port, sizeof(new_dst_port));
	bpf_printk("replace dst port %d", ret);
	ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, source), &new_src_port, sizeof(new_src_port));
	bpf_printk("replace src port %d", ret);

	uint32_t new_daddr = bpf_htonl(ack_ip);
	uint32_t new_saddr = header.ip->daddr;
	ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_daddr, sizeof(new_daddr));
	bpf_printk("replace dst ip %d", ret);
	ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, saddr), &new_saddr, sizeof(new_saddr));
	bpf_printk("replace src ip %d", ret);

	Elf32_Half check = 0;
	bpf_xdp_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
		sizeof(u16));

	header = try_parse_udp((void*) ctx->data ,(void*) ctx->data_end);
	if (header.udp != NULL)
		check = compute_ip_checksum(header.ip, (void*) ctx->data_end);
	bpf_xdp_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
		sizeof(u16));
	
	header = try_parse_udp((void*) ctx->data ,(void*) ctx->data_end);
	if (header.udp == NULL){
		return XDP_PASS;
	}
	__u8 src_mac[6];
	__u8 dst_mac[6];
	for (int i=0 ;i<6;i++){
		src_mac[i] = header.eth->h_source[i];
		dst_mac[i] = ack_mac[i];
	}

	ret = bpf_xdp_store_bytes(ctx, offsetof(struct ethhdr, h_dest), dst_mac, 6);
	bpf_printk("replace dst mac %d", ret);
	ret = bpf_xdp_store_bytes(ctx, offsetof(struct ethhdr, h_source), src_mac, 6);
	bpf_printk("replace src mac %d", ret);

	return XDP_TX;
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
