#pragma once
class SocketRawProgram
{
public:
	pcap_t* fp;
	char ttl = 128;
	int delay = 100;
	char errbuf[PCAP_ERRBUF_SIZE];
	SocketRawProgram();
	int InitRawSocket();
	bool ShowDevices();
	bool LoadConfigFromFile();
	int SendRawPacket(std::string descIp, std::string srcIp, int descPort, int srcPort);
	int CloseRawSocket();

private: 
	typedef struct iphdr
	{
		unsigned char  verlen;
		unsigned char  tos;
		unsigned short total_len;
		unsigned short ident;
		unsigned short frag_and_flags;
		unsigned char  ttl;
		unsigned char  proto;
		unsigned short checksum;
		unsigned int   sourceIP;
		unsigned int   destIP;

	} IPHEADER;

	typedef struct tcphdr
	{
		unsigned short srcPort;
		unsigned short dstPort;
		unsigned int   seq;
		unsigned int   ackSeq;
		unsigned char  lenres;
		unsigned char  flags;
		unsigned short window;
		unsigned short checksum;
		unsigned short urg_ptr;

	} TCPHEADER;

	// Our pseudo header struct
	typedef struct pshdr
	{
		unsigned int   daddr;
		unsigned int   saddr;
		unsigned char  zero;
		unsigned char  proto;
		unsigned short length;
	} PSDHEADER;

	typedef struct ethhdr
	{
		unsigned char macDsc[6];
		unsigned char macSrc[6];
		unsigned char type[2];
	} ETHHEADER;

	IPHEADER ipHeader;
	TCPHEADER tcpHeader;
	PSDHEADER psdHeader;
	ETHHEADER ethHeader;



	std::string nameDevice = "\Device\NPF_{CBCF66E9-BF6A-41B0-811C-DD1CD11B49A9}";
	std::string configFileName = "config.txt";
	

	unsigned long ResolveAddress(char* szHost);
	unsigned short CheckSum(unsigned short* buffer, int size);
	unsigned char* strToEthHdr(char* strMac);
};

