Simple program using arp poisoning to spoof HOST (in most cases - default gateway) and pcap filter to sniff dns request in local network on given INTERFACE and send fake answers with DEST_IP.
Copmilation: make
Usage: sudo ./dnsspoof HOST INTERFACE DEST_IP, eg. sudo ./dnsspoof 192.168.0.1 em1 51.254.121.149
