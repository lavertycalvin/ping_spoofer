#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* GLOBAL DEFS FOR SPOOFING */
char 			*device; 		//device used to sniff
pcap_t 			*handle; 		//session handle
char 			*spoof_ip_string;	//string ip address for sprintf
struct sockaddr_in 	spoof_ip_address; 	//designated spoofing ip
struct ether_addr  	*spoof_mac_address;  	//designated spoofing mac

struct bpf_program fp; /*compiled filter expression */

bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */


char filter_exp[100];
//capture all arp and ICMP traffic headed to the spoofed ip

/* END GLOBAL DEFS FOR SPOOFING */


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
void send_arp_response(); 	//response to arp request
void read_arp_request(); 	//process incoming arp request
void read_icmp_request(); 	//process incoming ping

void check_protocol(struct pcap_pkthdr header){
}

void listen_for_packets(){
	const u_char *live_packet;
	struct pcap_pkthdr header;
	while(1){
		if((live_packet = pcap_next(handle, &header)) != NULL){
			printf("Jacked a packet with length of [%d]\n", header.len);
			check_protocol(header);
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
