#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "ping_spoof.h"
#include "checksum.h"

/* GLOBAL DEFS FOR SPOOFING */
char 			*device; 		//device used to sniff
pcap_t 			*handle; 		//session handle
char 			*spoof_ip_string;	//string ip address for sprintf
struct sockaddr_in 	spoof_ip_address; 	//designated spoofing ip
char 			*spoof_mac_string;
struct ether_addr  	*spoof_mac_address;  	//designated spoofing mac

struct bpf_program fp; /*compiled filter expression */

bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */


char filter_exp[100];
//capture all arp and ICMP traffic headed to the spoofed ip

/* END GLOBAL DEFS FOR SPOOFING */

void strIP(struct in_addr ipAddr){
	fprintf(stdout, "%s", inet_ntoa(ipAddr));
}
void strMAC(struct ether_addr macAddr){
	fprintf(stdout, "%s", ether_ntoa(&macAddr));
}

/* parses input ip address, handles failures */
int parse_input_ip(char *input_ip){
	int ret = 0;
	if(!inet_pton(AF_INET, input_ip, &spoof_ip_address)){
		fprintf(stderr, "Unable to parse input IP address: %s, exiting...\n", input_ip);
		ret = 1;
	}
	return ret;
}

/* parses input mac address, handles failures */
int parse_input_mac(char *input_mac){
	int ret = 0;


	if((spoof_mac_address = ether_aton(input_mac)) != NULL){
		fprintf(stderr, "Unable to parse input MAC address: %s, exiting...\n", input_mac);
		ret = 1;
	}
	return ret;
}

int setup_pcap_filter(){
	int ret = 0;
	
	sprintf(filter_exp, "(arp or icmp) and host %s", spoof_ip_string);
	fprintf(stderr, "Filter expression: %s\n", filter_exp);
	
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		ret = 1;
	} 
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		ret = 1;
	}
	return ret;
}

int open_pcap_online(){
	int ret = 0;
	char errbuf[PCAP_ERRBUF_SIZE];	

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		ret = 1;
	}
	return ret;
}

int get_device(){
	int ret = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		ret = 1;
	}
	return ret;
}

void send_icmp_response(); 	//respond to ping

int parseUDPHeader(const u_char *pkt_data){
	struct udp_header *udp = (struct udp_header *)pkt_data;
	printUDPHeader(udp);
	return 0;
}

int parseICMPHeader(const u_char *pkt_data){	
	struct icmp_header *icmp = (struct icmp_header *)pkt_data;
	printICMPHeader(icmp);
	return 0;
}

void strPort(uint16_t port_num, int protocol){
	char *str_port = NULL;
	uint16_t host_order_port = ntohs(port_num);
	if(host_order_port == HTTP){
		str_port = "HTTP";	
	}
	else if(host_order_port == TELNET){
		str_port = "TELNET";	
	}
	else if(host_order_port == FTP){
		str_port = "FTP";	
	}
	else if(host_order_port == POP3){
		str_port = "POP3";	
	}
	else if(host_order_port == SMTP){
		str_port = "SMTP";	
	}
	else{} //leave as null for check

	//check to see if port was recognized
	if(str_port != NULL){
		fprintf(stdout, "%s", str_port);
	}
	else{
		fprintf(stdout, "%u", host_order_port);
	}
}

void strSeqNum(uint32_t num){
	fprintf(stdout, "%u", ntohl(num));
}

void strAckNum(uint32_t num){
	fprintf(stdout, "%u", ntohl(num));
}

void strTCPFlag(uint8_t flags, uint8_t mask){
	char *str_flag = NULL;
	if(flags & mask){
		str_flag = "Yes";
	}
	else{
		str_flag = "No";
	}
	fprintf(stdout, "%s", str_flag); 
}


void strWinSize(uint16_t window_size){
	fprintf(stdout, "%u", ntohs(window_size));
}

void strTCPChecksum(struct tcp_combo *tcp){
	unsigned short cksum_ret = 0;
 	unsigned short cksum_header = ntohs(tcp->header.tcp_checksum);
	int buf_size = 	ntohs(tcp->pseudo_header.tcp_seg_len) + sizeof(tcp->pseudo_header);

	cksum_ret = in_cksum((short unsigned int *)&tcp->pseudo_header, buf_size);
	
	if(cksum_ret != 0){
		fprintf(stdout, "Incorrect (0x%x)", cksum_header);
	}
	else{
		fprintf(stdout, "Correct (0x%x)", cksum_header);
	}
}
void printTCPHeader(struct tcp_combo *tcp){
	fprintf(stdout, "\n\n\tTCP Header");
	
	fprintf(stdout, "\n\t\tSource Port:  ");
	strPort(tcp->header.tcp_source_port, TCP_PROTO);
	
	fprintf(stdout, "\n\t\tDest Port:  ");
	strPort(tcp->header.tcp_dest_port, TCP_PROTO);	
	
	fprintf(stdout, "\n\t\tSequence Number: ");
	strSeqNum(tcp->header.tcp_seq_num);
	
	fprintf(stdout, "\n\t\tACK Number: ");
	strAckNum(tcp->header.tcp_ack_num);
	
	fprintf(stdout, "\n\t\tSYN Flag: ");
	strTCPFlag(tcp->header.tcp_flags, SYN_MASK);
	
	fprintf(stdout, "\n\t\tRST Flag: ");
	strTCPFlag(tcp->header.tcp_flags, RST_MASK);
	
	fprintf(stdout, "\n\t\tFIN Flag: ");
	strTCPFlag(tcp->header.tcp_flags, FIN_MASK);
	
	fprintf(stdout, "\n\t\tWindow Size: ");
	strWinSize(tcp->header.tcp_window_size);
	
	fprintf(stdout, "\n\t\tChecksum: ");
	strTCPChecksum(tcp);
}

void printUDPHeader(struct udp_header *udp){
	fprintf(stdout, "\n\n\tUDP Header");
	
	fprintf(stdout, "\n\t\tSource Port: ");
	strPort(udp->udp_source_port, UDP_PROTO);
	
	fprintf(stdout, "\n\t\tDest Port: ");
	strPort(udp->udp_dest_port, UDP_PROTO);
}

void strICMPType(uint8_t type){
	char *str_type = NULL;
	if(type == ICMP_REQUEST){
		str_type = "Request";
	}
	else if(type == ICMP_REPLY){
		str_type = "Reply";
	}
	else{
		str_type = "Unknown";
	}
	fprintf(stdout, "%s", str_type);
}
void printICMPHeader(struct icmp_header *icmp){
	fprintf(stdout, "\n\n\tICMP Header");
	
	fprintf(stdout, "\n\t\tType: ");
	strICMPType(icmp->icmp_type);
}
int parseTCPHeader(struct tcp_combo *combo){
	printTCPHeader(combo);
	return 0;
}
void strTOS(uint16_t tos){
	fprintf(stdout, "0x%x", tos);
}

void strTTL(uint8_t ip_ttl){
	fprintf(stdout, "%d", ip_ttl);
}

void strIPProtocol(uint8_t ip_protocol){
 	// Types accepted: TCP/UDP/ICMP/Unknown
	char *print_protocol = NULL;
	if(ip_protocol == ICMP){
		print_protocol = "ICMP";
	}
	else if(ip_protocol == UDP){
		print_protocol = "UDP";
	}
	else if(ip_protocol == TCP){
		print_protocol = "TCP";
	}
	else{
		print_protocol = "Unknown";
	}
	fprintf(stdout, "%s", print_protocol);
}

void strIPChecksum(struct ip_header *ip){
	unsigned short cksum_ret = 0;
	unsigned short ihl = (ip->ip_version & 0xf) * sizeof(uint32_t); //take off the upper bits
	unsigned short packet_checksum = ntohs(ip->ip_header_checksum);

	cksum_ret = in_cksum((short unsigned int *)&ip->ip_version, ihl);

	if(cksum_ret != 0){
		fprintf(stdout, "Incorrect (0x%x)", packet_checksum);
	}
	else{
		fprintf(stdout, "Correct (0x%x)", packet_checksum);
	}
	
}
void printIPHeader(struct ip_header *ip){
	fprintf(stdout, "\n\tIP Header");
	
	fprintf(stdout, "\n\t\tTOS: ");
	strTOS(ip->tos);
	
	fprintf(stdout, "\n\t\tTTL: ");
	strTTL(ip->ip_ttl);
	
	fprintf(stdout, "\n\t\tProtocol: ");
	strIPProtocol(ip->ip_protocol);
	
	fprintf(stdout, "\n\t\tChecksum: ");
	strIPChecksum(ip);
	
	fprintf(stdout, "\n\t\tSender IP: ");
	strIP(ip->ip_source_addr);
	
	fprintf(stdout, "\n\t\tDest IP: ");
	strIP(ip->ip_dest_addr);
}

int parseIPHeader(const u_char *pkt_data){
	int ip_ret = 0;
	struct ip_header *ip = (struct ip_header *)pkt_data;	
	unsigned short ihl = (ip->ip_version & 0xf) * sizeof(uint32_t); //take off the upper bits
	printIPHeader(ip);
	//decide on substructure to pass to
	if(ip->ip_protocol == ICMP){
		ip_ret = parseICMPHeader(&pkt_data[ihl]); 	
	}
	else if(ip->ip_protocol == UDP){
		ip_ret = parseUDPHeader(&pkt_data[ihl]);
	}
	else if(ip->ip_protocol == TCP){
      		//create tcp_pseudo header to pass info
      		struct tcp_combo *combo = malloc(sizeof(struct tcp_combo) + ntohs(ip->ip_len) - ihl);
		
		if(combo == NULL){
			fprintf(stderr, "Unable to malloc for TCP header\n");
			return 2; //indicate failure for different reason	
		}
		
		//set up pseudo tcp header
		combo->pseudo_header.ip_source_addr = ip->ip_source_addr;
      		combo->pseudo_header.ip_dest_addr = ip->ip_dest_addr;
      		combo->pseudo_header.reserved = 0;
      		combo->pseudo_header.protocol = ip->ip_protocol;
      		combo->pseudo_header.tcp_seg_len = htons(ntohs(ip->ip_len) - ihl);
		
		//set up tcp header
		memcpy(&combo->header, &pkt_data[ihl], sizeof(combo->header) + ntohs(ip->ip_len) - ihl); 
		
		ip_ret = parseTCPHeader(combo);
		free(combo);
	}
	else{
		//unknown type
		fprintf(stderr, "Unknown sub-IP Protocol.\n");
		ip_ret = 1;
	}
	return ip_ret;
}

void strOpcode(uint16_t opcode){
	if(ntohs(opcode) == ARP_REQUEST){
		fprintf(stdout, "Request");
	}
	else if(ntohs(opcode) == ARP_REPLY){
		fprintf(stdout, "Reply");
	}
	else{
		fprintf(stderr, "ARP Opcode not identified: %d", opcode);
	}
}

void printEthernetHeader(struct enet_header *ethHeader){
	printf("\tEthernet Header\n");
	
	printf("\t\tDest MAC: "); 
	strMAC(ethHeader->dest);
	
	printf("\n\t\tSource MAC: "); 
	strMAC(ethHeader->source);
	
	printf("\n\t\tType: "); 
	ethType(ethHeader->type);
}

void printARPHeader(struct arp_header *arp){
	fprintf(stdout, "\n\tARP Header");
	
	fprintf(stdout, "\n\t\tOpcode: ");
	strOpcode(arp->opcode);
	
	fprintf(stdout, "\n\t\tSender MAC: ");
	strMAC(arp->sender_mac);
	
	fprintf(stdout, "\n\t\tSender IP: ");
	strIP(arp->sender_ip);
	
	fprintf(stdout, "\n\t\tTarget MAC: ");
	strMAC(arp->target_mac);
	
	fprintf(stdout, "\n\t\tTarget IP: ");
	strIP(arp->target_ip);
}

void send_icmp_response(); 	//respond to ping


void copy_mac_address(struct ether_addr *src, struct ether_addr *dst){
	fprintf(stderr, "Copying in 'copy_mac_address'\n");
	for(int i=0; i<MAC_ADDR_LEN; i++){
		fprintf(stderr, "Copying %d byte...\n", i);
		dst[i] = src[i];	
	}
}

/*pkt_data points to the beginning of the packet to reply to */
void send_arp_response(const u_char *pkt_data){ 	//response to arp request
	printf("\ncallocing...\n");
	void *arp_packet = calloc(1, MIN_ETH_LENGTH);
	struct enet_header *ethHeader = (struct enet_header *)arp_packet;
	struct enet_header *request_eth_header = (struct enet_header *)pkt_data;
	printEthernetHeader(request_eth_header);
	struct arp_header *request_arp_header = (struct arp_header *)(++request_eth_header);
	printARPHeader(request_arp_header);
	
	printf("\nsetting ethernet header....\n");
	//setup ethernet header response
	ethHeader->dest = request_eth_header->source;
	//copy_mac_address(spoof_mac_address, &ethHeader->source);
	ethHeader->type = htons(ARP); 
	printEthernetHeader(ethHeader);	
	
	printf("setting arp header....\n");
	//setup arp header response
	struct arp_header *arp_response = (struct arp_header *)(++ethHeader);
	arp_response->hardware_addr_len = 6; //only 1 byte
	arp_response->hardware_type = htons(1); //Ethernet
	arp_response->opcode = htons(ARP_REPLY);
	arp_response->protocol_addr_len = 4; //only 1 byte
	arp_response->protocol_type = htons(IPV4);
	fprintf(stderr, "\t\t\tSpoofed IP Address: %s\n", inet_ntoa(spoof_ip_address.sin_addr));
	arp_response->sender_ip = spoof_ip_address.sin_addr; //spoofed ip address
	//copy_mac_address(spoof_mac_address, &arp_response->sender_mac);
	arp_response->target_ip = request_arp_header->sender_ip; //whoever sent
	arp_response->target_mac = request_arp_header->sender_mac; //whoever sent
	printARPHeader(arp_response);

	//send out arp response
	printf("arp packet ready to send....\n");
	free(arp_packet);
}

int parseARPHeader(const u_char *pkt_data){
 	struct arp_header *arp = (struct arp_header *)pkt_data;	
	printARPHeader(arp);
	//save all data here and respond appropriately
	if(ntohs(arp->opcode) == ARP_REQUEST){
		fprintf(stderr, "\t\t\tNeed to respond to this ARP request!\n");
		//pass the packet to the ARP building function
		send_arp_response(&pkt_data[-(sizeof(struct enet_header))]);
	}
	
	return 0;
}

void ethType(uint16_t type){
	char *etherType = NULL;
	if(ntohs(type) == ARP){
		etherType = "ARP";
	}
	else if(ntohs(type) == IPV4){
		etherType = "IP"; 
	}
	else {
		etherType = "Unknown";
	}
	
	printf("%s\n", etherType);//formatting
}


int parseEthernetHeader(const u_char *pkt_data){
	int subHeaderReturn = 0;
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	
	printEthernetHeader(ethHeader);
	
	//now pass on to correct sub-structure	
	if(ntohs(ethHeader->type) == ARP){
		subHeaderReturn = parseARPHeader(&pkt_data[sizeof(struct enet_header)]);
	}
	else if(ntohs(ethHeader->type) == IPV4){
		subHeaderReturn = parseIPHeader(&pkt_data[sizeof(struct enet_header)]);
	}
	else {
		fprintf(stderr, "Unable to parse substructure of Ethernet Header... Returning 1\n");
		subHeaderReturn = 1;
	}
	return subHeaderReturn;
}


int listen_for_packets(){
	int ret = 0;	
	const u_char *live_packet;
	struct pcap_pkthdr header;
	while(1){
		if((live_packet = pcap_next(handle, &header)) != NULL){
			printf("\n\nJacked a packet with length of [%d]\n\n", header.len);
			ret = parseEthernetHeader(live_packet); //has to be an ethernet header
			if(ret){
				fprintf(stderr, "Error parsing Ethernet packet\n");
			}
		}
	}
}

int main(int argc, char **argv){
	//check to see if all arguements are used
	if(argc != 3){
		fprintf(stderr, "Usage: ping_spoof <spoofed-mac-address> <spoofed-ip-address>\n");
		exit(1);
	}

	spoof_ip_string = argv[2];
	spoof_mac_string = argv[1];
	//check and store input mac and ip addresses
	if(parse_input_mac(argv[1]) || parse_input_ip(argv[2])){
		exit(1);
	}
	
	//get the device
	if(get_device()){
		exit(1);
	}
	//setup the online session
	if(open_pcap_online()){
		exit(1);
	}	
	//set up libpcap to filter for specific packets
	if(setup_pcap_filter()){
		exit(1);		
	}	
	
	fprintf(stderr, "\n============\n"
			"Spoofing as\n"
			"IP : %s\n"
		        "MAC: %s\n"
			"==============\n\n", argv[2], argv[1]);
	//must install sigint handler for ^C to work!
	fprintf(stderr, "Press ^C to exit...\n");
	
	
	//listen for packets and respond as appropriate
	listen_for_packets();	
	
	pcap_close(handle); //close the session
	return 0;
}
