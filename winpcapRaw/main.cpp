#define WIN32_LEAN_AND_MEAN
#define WIN32

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

typedef struct iphdr
{

	unsigned char  verlen;			// IP version & length
	unsigned char  tos;				// Type of service
	unsigned short total_len;		// Total length of the packet
	unsigned short ident;			// Unique identifier
	unsigned short frag_and_flags;	// Flags
	unsigned char  ttl;				// Time to live
	unsigned char  proto;			// Protocol (TCP, UDP etc)
	unsigned short checksum;		// IP checksum
	unsigned int   sourceIP;		// Source IP
	unsigned int   destIP;			// Destination IP

} IPHEADER;

typedef struct tcphdr
{

	unsigned short srcPort;			// Source port
	unsigned short dstPort;			// Destination port
	unsigned int   seq;				// Sequence number
	unsigned int   ackSeq;			// Acknowledgement number
	unsigned char  lenres;			// Length return size
	unsigned char  flags;			// Flags and header length
	unsigned short window;			// Window size
	unsigned short checksum;		// Packet Checksum
	unsigned short urg_ptr;			// Urgent Pointer

} TCPHEADER;

// Our pseudo header struct
typedef struct pshdr
{

	unsigned int   daddr;			// Destination address
	unsigned int   saddr;			// Source address

	unsigned char  zero;			// Placeholder
	unsigned char  proto;			// Protocol
	unsigned short length;			// TCP length
	//struct tcphdr tcp;				// TCP Header struct

} PSDHEADER;

typedef struct ethhdr  
{
	unsigned char macDsc[6];
	unsigned char macSrc[6];
	unsigned char type[2];
} ETHHEADER ;

unsigned long ResolveAddress(char* szHost)
{
	unsigned long ipv4addr;
	inet_pton(AF_INET, szHost, &ipv4addr);
	return ipv4addr;
}

unsigned short CheckSum(unsigned short* buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size) cksum += *(unsigned short*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

unsigned short csum(unsigned short* ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return(answer);
}

USHORT CheckSum1(USHORT* buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
		cksum += *(UCHAR*)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

u_short ChS(u_short* addr, int len) {
	register int nleft = len;
	register u_short answer;
	register int sum = 0;

	while (nleft > 1) {
		sum += *addr++;
		nleft -= 1;
	}

	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}



int main(int argc, char** argv)
{
	pcap_if_t *pt;
	char err;
	int iErr = pcap_findalldevs(&pt, &err);
	if (iErr == -1) {
		printf("error: %d\n" , err);
	}

	pcap_if_t* ptT;
	int iIdInterface = 1;
	printf("devices are available: ");
	for (ptT = pt ; ptT ; ptT = ptT->next)
	{
		printf("\n%d: ", iIdInterface++ );
		printf("\tdescription: \t%s\n", ptT->description);
		printf("\tname: \t\t%s\n", ptT->name );

	}


	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char packet[1200];
	int i;
	char nameDevice[] = "\Device\NPF_{CBCF66E9-BF6A-41B0-811C-DD1CD11B49A9}";

	/* Check the validity of the command line */
	if (argc != 2)
	{
		printf("usage: %s interface", argv[0]);
	//	return 1;
	}

	/* Open the adapter */
	if ((fp = pcap_open_live(nameDevice,		// name of the device
		65536,			// portion of the packet to capture. It doesn't matter in this case 
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 2;
	}

	memset(packet, 0, sizeof(packet));

	IPHEADER ipHeader;
	TCPHEADER tcpHeader;
	PSDHEADER psdHeader;
	ETHHEADER ethHeader;

	char ttl = 12;
	char ipDest[] = "192.168.0.102";
	char ipSrc[] = "192.168.0.112";
	unsigned short destPort = 80;
	unsigned short srcPort = 47512;
	//char payload[] = "GET / HTTP / 1.1\r\nHost: 192.168.0.104\r\n";
	char payload[] = "\n";

	ethHeader.macSrc[0] = 0xd0;
	ethHeader.macSrc[1] = 0x37;
	ethHeader.macSrc[2] = 0x45;
	ethHeader.macSrc[3] = 0x0b;
	ethHeader.macSrc[4] = 0xda;
	ethHeader.macSrc[5] = 0x86;

	ethHeader.macDsc[0] = 0xc0;
	ethHeader.macDsc[1] = 0x06;
	ethHeader.macDsc[2] = 0xc3;
	ethHeader.macDsc[3] = 0xec;
	ethHeader.macDsc[4] = 0x3a;
	ethHeader.macDsc[5] = 0xb6;

	ethHeader.type[0] = 8;
	ethHeader.type[1] = 0;


	ipHeader.verlen = (4 << 4 | sizeof(ipHeader) / sizeof(unsigned long)); //hex: 45 dec 69 
	ipHeader.tos = 0;
	ipHeader.total_len = htons(sizeof(ipHeader) + sizeof(tcpHeader) ); //2 bytes 
	ipHeader.ident = 1;
	ipHeader.frag_and_flags = 0;
	ipHeader.ttl = 60;
	ipHeader.proto = IPPROTO_TCP;
	ipHeader.checksum = 0;
	ipHeader.destIP = ResolveAddress( ipDest );
	ipHeader.sourceIP = ResolveAddress( ipSrc ) ;

	//tcp header
	tcpHeader.srcPort = htons(srcPort);
	tcpHeader.dstPort = htons(destPort);
	tcpHeader.seq = htons((unsigned short)((rand() << 4) | rand()));
	tcpHeader.ackSeq = 0;
	
	
	tcpHeader.lenres = (sizeof(tcpHeader) / 4 << 4 | 0); // tu albo jest 20 bez options lub 32 options
	tcpHeader.flags = 2;
	tcpHeader.window = 512;
	tcpHeader.urg_ptr = 0;
	tcpHeader.checksum = 0;

	psdHeader.daddr = ipHeader.destIP;
	psdHeader.saddr = ipHeader.sourceIP;
	psdHeader.zero = 0;
	psdHeader.proto = IPPROTO_TCP;
	psdHeader.length = htons( sizeof(tcpHeader) ) ;

	memcpy(packet , &psdHeader, sizeof(psdHeader));
	memcpy(packet + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
	tcpHeader.checksum = CheckSum( (unsigned short*) packet , ( sizeof(tcpHeader) + sizeof( psdHeader  ) ) ) ;

	memset(packet, 0, sizeof(packet));
	memcpy(packet, &ipHeader, sizeof(ipHeader));
	ipHeader.checksum = CheckSum((unsigned short*)packet, sizeof(ipHeader)  );

	
	memcpy(packet, &ethHeader, sizeof(ethHeader));
	memcpy(packet + sizeof(ethHeader), &ipHeader, sizeof(ipHeader));
	memcpy(packet + sizeof(ethHeader) + sizeof(ipHeader ), &tcpHeader, sizeof(tcpHeader)); 

	int sizeP = sizeof(ethHeader) + sizeof(ipHeader) + sizeof(tcpHeader) ;

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet ,				// buffer with the packet
		sizeP					// size
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);
	return 0;
}