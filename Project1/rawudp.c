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
	//unsigned short int iph_flag:4, iph_offset:12;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
};
// total IP header length: 20 bytes (=160 bits)

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

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}



// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[])
{
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

	memset(buffer, 0, PCKT_LEN);

	if(argc != 5)
	{
		printf("- Invalid parameters!!!\n");
		printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
		exit(-1);
	}

	// Create a raw socket with UDP protocol
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0)
	{
		perror("socket() error");

		// If something wrong just exit
		exit(-1);
	}else
		printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");

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
	ip->iph_ident = htons(54321);
	ip->iph_flagnoffset = htons(0x4000);
	//ip->iph_offset = 64;
	//ip->iph_flag = 7;
	ip->iph_ttl = 64; // hops
	ip->iph_protocol = 17; // UDP
	// Source IP address, can use spoofed address here!!!
	ip->iph_sourceip = inet_addr(argv[1]);

	// The destination IP address
	ip->iph_destip = inet_addr(argv[3]);

	// Calculate the checksum for integrity
	ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader));

	// Fabricate the UDP header. Source port number, redundant
	udp->udph_srcport = htons(atoi(argv[2]));

	// Destination port number
	udp->udph_destport = htons(atoi(argv[4]));

	

	struct dnsheader *dnsh = (struct dnsheader * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
	dnsh->dnsh_id = htons((unsigned short int)rand());
	dnsh->dnsh_qr = 0;
	dnsh->dnsh_opcode = 0;
	dnsh->dnsh_aa = 0;
	dnsh->dnsh_tc = 0;
	dnsh->dnsh_rd = 1;
	dnsh->dnsh_ra = 0;
	dnsh->dnsh_z = 0;
	dnsh->dnsh_qdcount = htons(1);
	dnsh->dnsh_ancount = 0;
	dnsh->dnsh_nscount = 0;
	dnsh->dnsh_arcount = htons(1);

	unsigned char domain_name[] = "isc.org";
	// Standard DNS Domain Name Notation
	// e.g. "www.nctu.edu.tw" -> "3www4nctu3edu2tw0"
	unsigned char dnsq_dname[strlen((char *)domain_name)+2];

	int pos, point_cnt = 0;
	dnsq_dname[0] = '.';
	dnsq_dname[strlen((char *)domain_name)+1] = 0;
	for(pos = strlen((char *)domain_name); pos >= 0; pos--)
	{
		point_cnt++;
		if(pos-1 >= 0)
			dnsq_dname[pos] = domain_name[pos-1];
		if(dnsq_dname[pos] == '.')
		{
			dnsq_dname[pos] = point_cnt-1;
			point_cnt = 0;
		}
	}

	unsigned char *ptr = (unsigned char * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
	for(pos = 0; pos <= strlen((char *)domain_name)+1; pos++)
	{
		*ptr = dnsq_dname[pos];
		*ptr++;
	}

	struct dnsquery *dnsq = (struct dnsquery * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(dnsq_dname));
	dnsq->dnsq_qclass = htons(0x0001);
	dnsq->dnsq_qtype = htons(0x00ff);

	struct dnsadditional *dnsa = (struct dnsadditional * ) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(dnsq_dname) + sizeof(struct dnsquery) + 1);
	dnsa->dnsa_type = htons(41);
	dnsa->dnsa_udppayloadsize = htons(512);

	ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(dnsq_dname) + sizeof(struct dnsquery) + sizeof(struct dnsadditional) + 1;
	udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(dnsq_dname) + sizeof(struct dnsquery) + sizeof(struct dnsadditional) + 1);

	//ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
	//udp->udph_len = htons(sizeof(struct udpheader));

	// Inform the kernel do not fill up the packet structure. we will build our own...
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		exit(-1);
	}else
		printf("setsockopt() is OK.\n");

	// Send loop, send for every 2 second for 100 count
	printf("Trying...\n");
	printf("Using raw socket and UDP protocol\n");
	printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

	int count;
	for(count = 1; count <=1; count++)
	{
		if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		// Verify
		{
			perror("sendto() error");
			exit(-1);
		}else
		{
			printf("Count #%u - sendto() is OK.\n", count);
			sleep(2);
		}
	}
	close(sd);
	return 0;
}
