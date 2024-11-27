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


static __always_inline struct hdr try_parse_udp(void* data, void* data_end);

#define SERVER_COUNT 1

__u16 redirect_port = 12346;
__u16 server_ports[SERVER_COUNT] = {
	12345,
};

SEC("tc")
int tcdump(struct __sk_buff *ctx) {
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	struct hdr header = try_parse_udp(data, data_end);

	if (header.udp == NULL) {
		bpf_printk("not udp packet\n");
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
	if(ip->protocol != IP_P_UDP)
		return (struct hdr) {NULL,NULL, NULL};
	
	if(data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct udphdr* udp = data + ETH_SIZE + IP_SIZE;

	

	return (struct hdr){eth,ip, udp};
}


