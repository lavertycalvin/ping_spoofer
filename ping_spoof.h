/* Header file for trace.c */

#ifndef TRACE_H
#define TRACE_H


#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* ================ Ethernet Header defs ================ */
#define MIN_ETH_LENGTH 60
#define MAC_ADDR_LEN 6


#define ARP  0x0806 
#define IPV4 0x0800

/*14 bytes consumed by the ethernet header*/
struct enet_header {
	struct ether_addr dest;
	struct ether_addr source;
	uint16_t type; /*ARP, IP, Unknown*/
}__attribute__((packed));


void ethType(uint16_t type);
int parseEthernetHeader(const u_char *pkt_data);
void printEthernetHeader(struct enet_header *ethHeader);

/*  ================= end Ethernet Header defs ============  */

/*  =================== link layer defs ===================  */
#define ARP_REQUEST 	1
#define ARP_REPLY 	2 

#define ICMP 		1
#define TCP		6
#define UDP		17

struct arp_header{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t  hardware_addr_len;
	uint8_t  protocol_addr_len;
	uint16_t opcode; 		
	struct ether_addr  sender_mac; 	
	struct in_addr sender_ip;     	
	struct ether_addr  target_mac; 	
	struct in_addr target_ip;		
}__attribute__((packed));

struct ip_header{
	uint8_t  ip_version; 		//0-3 bits are version, 4-7 are ihl
	uint8_t tos; 			//type of service or DSCP
	uint16_t ip_len; 		//entire packet length including header and data
	uint16_t ip_id; 		//
	uint16_t ip_flags_and_offset; 	//0-2 bits are flags, last are fragment offset
	uint8_t  ip_ttl; 		//time to live
	uint8_t  ip_protocol; 		//TCP/UDP/ICMP/Unknown
	uint16_t ip_header_checksum; 	//error checking
	struct in_addr ip_source_addr; 	//
	struct in_addr ip_dest_addr;   	//
	uint64_t ip_options_1;	 	//
	uint64_t ip_options_2;   	//
}__attribute__((packed));

int parseIPHeader(const u_char *pkt_data);
int parseARPHeader(const u_char *pkt_data);
void printIPHeader(struct ip_header *ip);
void printARPHeader(struct arp_header *arp);
/*  ===================  end link layer =======================*/

/*  ================= transport layer defs ====================*/

/*tcp flag defines */
#define FIN_MASK	0x1
#define SYN_MASK 	0x2
#define RST_MASK	0x4

/*icmp type defines */
#define ICMP_REQUEST 	0x8 		//stored in type field
#define ICMP_REPLY	0x0 		//stored in type field

/* transport layer protocol defs */
#define TCP_PROTO 	0x0
#define UDP_PROTO	0x1

/* Common port defs */
#define FTP		21
#define TELNET		23
#define SMTP		25
#define HTTP		80
#define POP3		110

struct tcp_header{
	uint16_t tcp_source_port;
	uint16_t tcp_dest_port;
	uint32_t tcp_seq_num;
	uint32_t tcp_ack_num;
	uint8_t  tcp_data_offset; 	//0-3 offset, 4-6 reserved, 7 NS flag
	uint8_t  tcp_flags; 		//check header info
	uint16_t tcp_window_size;
	uint16_t tcp_checksum;
	uint16_t tcp_urgent_pointer;
	u_char data[];			//flexible array member: data past the tcp header
}__attribute__((packed));

struct tcp_pseudo_header{
	struct in_addr ip_source_addr;
	struct in_addr ip_dest_addr;
	uint8_t  reserved;
	uint8_t  protocol;
	uint16_t tcp_seg_len;
}__attribute__((packed));

/* hold tcp pseudo header and header consecutively for checksum computation*/
struct tcp_combo{
	struct tcp_pseudo_header pseudo_header;
	struct tcp_header header;
}__attribute__((packed));

struct udp_header{
	uint16_t udp_source_port;
	uint16_t udp_dest_port;
	uint16_t udp_len;
	uint16_t udp_checksum;
}__attribute__((packed));

struct icmp_header{
	uint8_t  icmp_type; 		//request, reply, unknown
	uint8_t  icmp_code;
	uint16_t icmp_checksum;
	u_char  icmp_leftover[0];
}__attribute__((packed));


void strMAC(struct ether_addr macAddr);
void strIP(struct in_addr ipAddr);

int parseTCPHeader(struct tcp_combo *combo);
int parseUDPHeader(const u_char *pkt_data);
int parseICMPHeader(const u_char *pkt_data, unsigned short ihl, unsigned short pkt_and_data_length);

void printTCPHeader(struct tcp_combo *tcp);
void printUDPHeader(struct udp_header *udp);
void printICMPHeader(struct icmp_header *icmp);
/* ===================== end transport layer =======================*/
#endif
