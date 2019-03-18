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
    unsigned short int iph_flag_and_offset;
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

void dns_domain_format(unsigned char *all_headers, unsigned char *host){
	strcat((char *)host, ".");

	// indicate the position where previous word end.
	int placeholder = 0;

	for(int i = 0; i <= strlen((char *)host); i++){

		if(host[i] == '.'){
			// replace the dot with current word's length
			*all_headers = i - placeholder;
			all_headers++;

			// shift right 1 byte for all the letters in this word 
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

    int sd;

    // No data/payload just datagram
    char buffer[PCKT_LEN];
    // Our own headers' structures
    struct ipheader   *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader*) (buffer + sizeof(struct ipheader));

    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN); //clear buffer
    
    // check commanf line arguments format
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

    // Socket infos
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = htons(atoi(argv[2]));
    din.sin_port = htons(atoi(argv[4]));
    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    din.sin_addr.s_addr = inet_addr(argv[3]);
    

    // Fabricate the IP header 
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;  
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(getpid());
    ip->iph_flag_and_offset = htons(0x4000);
    ip->iph_ttl = 64;      // hops
    ip->iph_protocol = 17; // UDP
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);
    // The destination IP address
    ip->iph_destip = inet_addr(argv[3]);
    

    // Fabricate the UDP header.
    udp->udph_srcport  = htons(atoi(argv[2]));
    udp->udph_destport = htons(atoi(argv[4]));
    udp->udph_len = htons(sizeof(struct udpheader));
    udp->udph_chksum = htons(0);


    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader));
    udp->udph_chksum = 


    // Setup DNS header
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
	dns->query_id = (unsigned short) htons(getpid());
	dns->flags = htons(0x0100);
	dns->q_count = htons(1);
	dns->ans_count  = 0;
	dns->auth_count = 0;
	dns->add_count  = 0;


    // format the domain name in DNS query
    unsigned char *packet_headers;
    packet_headers = (unsigned char *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
    unsigned char dns_domain[] = "www.google.com";
    int domain_len = strlen((const char *)dns_domain) + 2;
	
    dns_domain_format(packet_headers, dns_domain);
	
    //payload: DNS query
	struct dnsquery *q;
	q = (struct dnsquery *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len);
	q->qtype  = htons(0x00ff);  // ANY ??
	q->qclass = htons(0x0001);  // IN
    

    // modify header lengths
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + domain_len + sizeof(struct dnsquery));


    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        perror("setsockopt() error");
        exit(-1);
    }
    else{
        printf("setsockopt() is OK.\n");
    }


    // Send loop, send for every 5 second for 5 count
    printf("Trying...\n");
    printf("Using raw socket and UDP protocol\n");
    printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

    for(int count = 1; count <= 2; count++){
        
        // Verify
        if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            perror("sendto() error");   
            exit(-1);
        }
        else{
            printf("Count #%u - sendto() is OK.\n", count);
            sleep(5);
        }
    }
    close(sd);
    return 0;
}