#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "ping_spoof.h"
#include "checksum.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "smartalloc.h"
#include <signal.h>

/* GLOBAL DEFS FOR SPOOFING */
char 			*device; 		//device used to sniff
pcap_t 			*handle; 		//session handle
struct sockaddr_in 	spoof_ip_address; 	//designated spoofing ip
struct ether_addr 	*spoof_mac_address;  	//designated spoofing mac
int 			socket_fd; 		//file descriptor used by socket
struct sockaddr_ll 	response_socket_address;//response socket!
struct ifreq		interface; 		//interface (device?);
int 			interface_index;
u_char 			interface_mac[6];

/* packets used to  send */
void *arp_packet;
void *sending_packet; //icmp packet

struct bpf_program fp; /*compiled filter expression */

bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */


char filter_exp[100]; //capture all arp and ICMP traffic headed to the spoofed ip

/* END GLOBAL DEFS FOR SPOOFING */

/* parses input ip address, handles failures */
int parse_input_ip(char *input_ip){
	int ret = 0;
	if(!inet_pton(AF_INET, input_ip, &(spoof_ip_address.sin_addr))){
		fprintf(stderr, "Unable to parse input IP address: %s, exiting...\n", input_ip);
		ret = 1;
	}
	return ret;
}

/* parses input mac address, handles failures */
int parse_input_mac(char *input_mac){
	int ret = 0;

	if((spoof_mac_address = ether_aton(input_mac)) == NULL){
		fprintf(stderr, "Unable to parse input MAC address: %s, exiting...\n", input_mac);
		ret = 1;
	}
	return ret;
}

int setup_pcap_filter(){
	int ret = 0;
	
	sprintf(filter_exp, "(arp or icmp) and dst host %s", inet_ntoa(spoof_ip_address.sin_addr));
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
	
	//request raw socket
	if((socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("Failure in requesting socket for arp response:");
		exit(1);
	}

	//get interface index to use for sending ethernet frames
	strcpy(interface.ifr_name, device);
	if(ioctl(socket_fd, SIOCGIFINDEX, &interface) < 0){
		perror("ioctl() device: ");
		exit(1);
	}
	interface_index = interface.ifr_ifindex;	

	return ret;
}

/*respond to the ping that was sent 
 * resp_pkt_size should be ip header length + rest of data
 */
void send_icmp_response(const u_char *pkt_data, unsigned short ihl, unsigned short resp_pkt_size){
	sending_packet = NULL;

	int packet_length = sizeof(struct enet_header) + resp_pkt_size;
	if(packet_length < MIN_ETH_LENGTH){
		packet_length = MIN_ETH_LENGTH;
	}

	sending_packet = calloc(1, packet_length);
	if(!sending_packet){
		perror("Calloc for send_icmp_response(): ");
		exit(1);
	}
	
	//fill out ethernet header
	struct enet_header *received_enet_header = (struct enet_header *)&pkt_data[-(ihl + sizeof(struct enet_header))];
	struct enet_header *response_enet_header = (struct enet_header *)sending_packet;
	response_enet_header->source = received_enet_header->dest;
	response_enet_header->dest   = received_enet_header->source;
	response_enet_header->type   = htons(IPV4);
	
	//fill out ICMP header
	struct icmp_header *response_icmp_header = (struct icmp_header *)&((u_char *)sending_packet)[ihl + sizeof(struct enet_header)];
	struct icmp_header *received_icmp_header = (struct icmp_header *)pkt_data;
	response_icmp_header->icmp_type = 0;
	response_icmp_header->icmp_code = 0;

	//copy over the payload
	u_char *received_icmp_payload = received_icmp_header->icmp_leftover;
	int payload_size = resp_pkt_size - ihl - 4;
	int i = 0;
   for(i = 0; i < payload_size; i++){
		response_icmp_header->icmp_leftover[i] = received_icmp_payload[i];
	}
	
	response_icmp_header->icmp_checksum = in_cksum((unsigned short *)response_icmp_header, payload_size + 4); //set to 0 before calculating the checksum
	
	//fill out IPv4 header
	struct ip_header *received_ip_header = (struct ip_header *)&pkt_data[-(ihl)];
	struct ip_header *response_ip_header = (struct ip_header *)&((u_char *)sending_packet)[sizeof(struct enet_header)];
	response_ip_header->ip_version     = received_ip_header->ip_version;
	response_ip_header->ip_dest_addr   = received_ip_header->ip_source_addr;
        response_ip_header->ip_source_addr = spoof_ip_address.sin_addr;
	response_ip_header->ip_len         = htons(resp_pkt_size); //entire packet size (min is 20 which is JUST the ip header)
	response_ip_header->ip_id          = 0;
	response_ip_header->ip_ttl         = 64; //max ttl
	response_ip_header->ip_version     = received_ip_header->ip_version; //first 4 bits are version, last 4 are ihl
	response_ip_header->ip_protocol    = ICMP;
	response_ip_header->ip_flags_and_offset = 0;
	response_ip_header->ip_header_checksum  = in_cksum((unsigned short *)response_ip_header, resp_pkt_size);

	//set destination for the packet
	for(i = 0; i < MAC_ADDR_LEN; i++){
		response_socket_address.sll_addr[i] = response_enet_header->dest.ether_addr_octet[i];
	}
	response_socket_address.sll_addr[6]  = 0;
	response_socket_address.sll_addr[7]  = 0;
	response_socket_address.sll_family   = AF_PACKET; 
	response_socket_address.sll_halen    = 6;
	response_socket_address.sll_hatype   = htons(ARPHRD_ETHER);
	response_socket_address.sll_ifindex  = interface_index; //needs to change to the right index
	response_socket_address.sll_pkttype  = PACKET_OTHERHOST;
	response_socket_address.sll_protocol = htons(ETH_P_IP);

	int sent_bytes = 0;
	if((sent_bytes = sendto(socket_fd, sending_packet, packet_length, 0, (struct sockaddr *)&response_socket_address, sizeof(response_socket_address))) == -1){
		perror("ICMP Sendto():");
		exit(1);
	}
	free(sending_packet);
	sending_packet = NULL;
}

int parseICMPHeader(const u_char *pkt_data, unsigned short ihl, unsigned short pkt_and_data_length){	
	struct icmp_header *icmp = (struct icmp_header *)pkt_data;
	
	//if this is an echo request, we must make a reply
	if(icmp->icmp_type == ICMP_REQUEST){
		send_icmp_response(pkt_data, ihl, pkt_and_data_length);
	}
	return 0;
}

int parseIPHeader(const u_char *pkt_data){
	int ip_ret = 0;
	struct ip_header *ip = (struct ip_header *)pkt_data;	
	unsigned short ihl = (ip->ip_version & 0x0f) * sizeof(uint32_t); //take off the upper bits
	
	//make sure the internet checksum is correct!
	if(in_cksum((unsigned short *)ip, ntohs(ip->ip_len)) !=0){
		fprintf(stderr, "Skipping packet with incorrect checksum!\n");
		return 0;
	}
	
	//decide on substructure to pass to
	if(ip->ip_protocol == ICMP){
		ip_ret = parseICMPHeader(&pkt_data[ihl], ihl, ntohs(ip->ip_len)); 	
	}
	return ip_ret;
}

/* configure the socket to send out the arp packet */
void send_to_arp_socket(void *arp_packet){
	int sent_bytes = 0;
	//the rest of .sll_addr are set in calling function
	response_socket_address.sll_addr[6]  = 0;
	response_socket_address.sll_addr[7]  = 0;
	response_socket_address.sll_family   = AF_PACKET; 
	response_socket_address.sll_halen    = 6;
	response_socket_address.sll_hatype   = htons(ARPHRD_ETHER);
	response_socket_address.sll_ifindex  = interface.ifr_ifindex; //needs to change to the right index
	response_socket_address.sll_pkttype  = PACKET_OTHERHOST;
	response_socket_address.sll_protocol = htons(ETH_P_ARP);

	if((sent_bytes = sendto(socket_fd, arp_packet, MIN_ETH_LENGTH, 0, (struct sockaddr *)&response_socket_address, sizeof(response_socket_address))) == -1){
		perror("ARP Sendto():");
		exit(1);
	}

}

/*pkt_data points to the beginning of the packet to reply to */
void send_arp_response(const u_char *pkt_data){ 	//response to arp request
	arp_packet = calloc(1, MIN_ETH_LENGTH);
	struct enet_header *ethHeader = (struct enet_header *)arp_packet;
	struct enet_header *request_eth_header = (struct enet_header *)pkt_data;
	struct arp_header *request_arp_header = (struct arp_header *)(&pkt_data[14]);
	
	//setup ethernet header response
	ethHeader->dest = request_eth_header->source;
	ethHeader->source = *spoof_mac_address;
	ethHeader->type = htons(ARP); 
	//printEthernetHeader(ethHeader);	
	
	//setup arp header response
	struct arp_header *arp_response = (struct arp_header *)(++ethHeader);
	arp_response->hardware_type = htons(1); //Ethernet
	arp_response->protocol_type = htons(IPV4);
	arp_response->hardware_addr_len = 6; //only 1 byte
	arp_response->protocol_addr_len = 4; //only 1 byte
	arp_response->opcode = htons(ARP_REPLY);
	arp_response->sender_mac = *spoof_mac_address;
	arp_response->sender_ip = spoof_ip_address.sin_addr; //spoofed ip address
	arp_response->target_mac = request_arp_header->sender_mac; //whoever sent
	arp_response->target_ip = request_arp_header->sender_ip; //whoever sent
	//printARPHeader(arp_response);

	//set destination for the packet
	int i = 0;
   for(i = 0; i < MAC_ADDR_LEN; i++){
		response_socket_address.sll_addr[i] = arp_response->target_mac.ether_addr_octet[i];
	}
	
	//send packet over the wire
	send_to_arp_socket(arp_packet);	
	free(arp_packet);
	arp_packet = NULL;
}

int parseARPHeader(const u_char *pkt_data){
 	struct arp_header *arp = (struct arp_header *)pkt_data;	
	//save all data here and respond appropriately
	if(ntohs(arp->opcode) == ARP_REQUEST){
		//pass the packet to the ARP building function
		send_arp_response(&pkt_data[-sizeof(struct enet_header)]);
	}
	
	return 0;
}

int parseEthernetHeader(const u_char *pkt_data){
	int subHeaderReturn = 0;
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	
	//printEthernetHeader(ethHeader);
	
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
			ret = parseEthernetHeader(live_packet); //has to be an ethernet header
			if(ret){
				fprintf(stderr, "Error parsing Ethernet packet\n");
			}
		}
	}
}


void int_handler(int sig){
	fprintf(stdout,"\nExiting....\n");
	if(arp_packet != NULL){
		free(arp_packet);
	}
	if(sending_packet != NULL){
		free(sending_packet);
	}
	exit(0);
}

int main(int argc, char **argv){
	//check to see if all arguements are used
	if(argc != 3){
		fprintf(stderr, "Usage: ping_spoof <spoofed-mac-address> <spoofed-ip-address>\n");
		exit(1);
	}

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
			"Spoofing on device %s\n"
			"IP : %s\n"
		        "MAC: %s\n"
			"==============\n\n", device, inet_ntoa(spoof_ip_address.sin_addr), ether_ntoa(spoof_mac_address));
	fprintf(stderr, "Press ^C to exit...\n");
	
	//install signal handler
	signal(SIGINT, int_handler);
	//listen for packets and respond as appropriate
	listen_for_packets();	
	
	pcap_close(handle); //close the session
	return 0;
}
