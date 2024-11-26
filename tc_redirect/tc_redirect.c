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



SEC("tc")
int tcdump(struct __sk_buff *ctx) {
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	struct hdr header = try_parse_udp(data, data_end);

	if (header.udp == NULL) {
		bpf_printk("not udp packet\n");
		return TC_ACT_OK;
	}

	//print mac, addr, port,
	bpf_printk("================tc===================\n");
	bpf_printk("dest mac: %x:%x:%x:%x:%x:%x\n", header.eth->h_dest[0], header.eth->h_dest[1], header.eth->h_dest[2], header.eth->h_dest[3], header.eth->h_dest[4], header.eth->h_dest[5]);
	bpf_printk("source mac: %x:%x:%x:%x:%x:%x\n", header.eth->h_source[0], header.eth->h_source[1], header.eth->h_source[2], header.eth->h_source[3], header.eth->h_source[4], header.eth->h_source[5]);
	u32 daddr = header.ip->daddr;
	u32 saddr = header.ip->saddr;
	bpf_printk("dest addr: %d.%d.%d.%d\n", daddr & 0xFF, (daddr >> 8) & 0xFF, (daddr >> 16) & 0xFF, (daddr >> 24) & 0xFF);
	bpf_printk("source addr: %d.%d.%d.%d\n", saddr & 0xFF, (saddr >> 8) & 0xFF, (saddr >> 16) & 0xFF, (saddr >> 24) & 0xFF);
	bpf_printk("dest port: %d\n", bpf_ntohs(header.udp->dest));
	bpf_printk("source port: %d\n", bpf_ntohs(header.udp->source));
	bpf_printk("================tc===================\n");
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


