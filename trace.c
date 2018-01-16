/* Author        : Calvin Laverty
 * Last Modified : 9/30/17
 * Overview: Pass in a single pcap file for header parsing.
 * 	Header Support:
 * 		Ethernet II
 * 		ARP, ICMP
 * 		TCP, UDP
 *
 * NOTE: checksum.h and checksum.c are NOT my personal property. 
 * I had no contribution to these files
 */

#include <stdlib.h>
#include <string.h>

#include "trace.h"
#include "checksum.h"

/* multi-layer functions */
void strIP(struct in_addr ipAddr){
	fprintf(stdout, "%s", inet_ntoa(ipAddr));
}

void strMAC(struct ether_addr macAddr){
	fprintf(stdout, "%s", ether_ntoa(&macAddr));
}
/* end multi-layer functions */

/* transport layer */
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

/* str functions for TCP Header */
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
/*end str functions for TCP Header */

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

void printICMPHeader(struct icmp_header *icmp){
	fprintf(stdout, "\n\n\tICMP Header");
	
	fprintf(stdout, "\n\t\tType: ");
	strICMPType(icmp->icmp_type);
}

int parseTCPHeader(struct tcp_combo *combo){
	printTCPHeader(combo);
	return 0;
}

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

/* end transport layer */
/* link layer */

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

int parseARPHeader(const u_char *pkt_data){
 	struct arp_header *arp = (struct arp_header *)pkt_data;	
	printARPHeader(arp);
	return 0;
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
/* end link layer */

/* physical layer */
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

void printEthernetHeader(struct enet_header *ethHeader){
	printf("\tEthernet Header\n");
	
	printf("\t\tDest MAC: "); 
	strMAC(ethHeader->dest);
	
	printf("\n\t\tSource MAC: "); 
	strMAC(ethHeader->source);
	
	printf("\n\t\tType: "); 
	ethType(ethHeader->type);
}
/* end physical layer */

/* design: peel off a layer an pass to next layer */
int parsePacket(pcap_t *pcapSaveFile) {
	int eNetHeaderRet = 0;
	struct pcap_pkthdr *header = NULL;
	const u_char *pkt_data = NULL;
	int packetsRead = 0;
	
	//loop through until we don't have anymore saved packets
	while (pcap_next_ex(pcapSaveFile, &header, &pkt_data) != -2) {
		packetsRead++;
		
		fprintf(stdout, "\nPacket number: %d  ", packetsRead); 
		fprintf(stdout, "Packet Len: %d\n\n", header->len);
		
		eNetHeaderRet = parseEthernetHeader(pkt_data);
		fprintf(stdout, "\n"); //formatting for multiple packets
	}	
	return eNetHeaderRet;
}

/* will return null if pcap_open_offline is null */
pcap_t *openPcapFile(char *fileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapInfo = NULL;
	if ((pcapInfo = pcap_open_offline(fileName, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open pcap file! Error: %s\n", errbuf);
	}
	return pcapInfo;
}

int main(int argc, char **args) {
	//only take one pcap file as an input
	int parseRet = 0;
	pcap_t *pcapInfo = NULL;
	if (argc != 2) {
		fprintf(stderr, "Illegal Use: Please provide a single pcap file\n");
		parseRet = 1;
	}	
	else if ((pcapInfo = openPcapFile(args[1])) == NULL) {
		parseRet = 1;
	}
	else{
		parseRet = parsePacket(pcapInfo);
	}
	exit(parseRet);
}
