// ----rawudp.c------
// Must be run by root lol! Just datagram, no payload/data

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// The packet length
#define PCKT_LEN 8192

// Can create separate header file (.h) for all headers' structure

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flag:3;
    unsigned short int iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
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
	unsigned short int query_id;
	unsigned short int flags;
	unsigned short int q_count;
	unsigned short int ans_count;
	unsigned short int auth_count;
	unsigned short int add_count;
};

struct dnsquery{
    unsigned short int qtype;
    unsigned short int qclass;
};



//  Function for checksum calculation. From the RFC,
//  the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."

unsigned short csum(unsigned short *buf, int nwords){       //
    unsigned long sum;

    for(sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}


// format dns query's domain name
// example: turn "www.google.com" into "3www6google3com0"
void dns_query_format(unsigned char *dns, unsigned char *host){
	int lock = 0, i;
	strcat((char*)host, ".");
	for(i = 0 ; i < strlen((char*)host) ; i++) {
		if(host[i]=='.'){
			*dns++ = i-lock;
			for(; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;  // indicate the end of the string
}


// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[]){

    int sd;

    // No data/payload just datagram
    char buffer[PCKT_LEN];
    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    // struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN);
    
    if(argc != 5){
        printf("- Invalid parameters!!!\n");
        printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
        exit(-1);
    }

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0){
        perror("socket() error");
        exit(-1);  // If something wrong just exit
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
    ip->iph_tos = 16; // Low delay
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = 64; // hops
    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);

    // The destination IP address
    ip->iph_destip = inet_addr(argv[3]);

    
    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(atoi(argv[2]));
    // Destination port number
    udp->udph_destport = htons(atoi(argv[4]));
    udp->udph_len = htons(sizeof(struct udpheader));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));


    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
	dns->query_id = (unsigned short) htons(getpid());
	dns->flags = htons(0x0100);
	dns->q_count = htons(1);
	dns->ans_count  = 0;
	dns->auth_count = 0;
	dns->add_count  = 0;


    unsigned char *packet_headers;
    packet_headers = (unsigned char *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
	
    // dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
	// strcpy(dns_rcrd, dns_record);

    unsigned char dns_domain[] = "www.google.com";
    unsigned char *dns_domain_save;
	strcpy(dns_domain, dns_domain_save);

    int domain_len = strlen((const char *)dns_domain_save)+2);
	dns_query_format(packet_headers, dns_domain);
	



	struct dnsquery *q;
	q = (struct dnsquery *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len);
	q->qtype  = htons(0x00ff);  // ANY ??
	q->qclass = htons(0x0001);  // IN
    


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

    int count;
    for(count = 1; count <=10; count++){
        
        // Verify
        if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
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