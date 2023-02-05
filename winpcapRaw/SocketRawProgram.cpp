#define WIN32_LEAN_AND_MEAN
#define WIN32


#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#include <pcap.h>

#include "SocketRawProgram.h"



using namespace std;

int SocketRawProgram::InitRawSocket() {

		/* Open the adapter */
	if ((fp = pcap_open_live(nameDevice.c_str(),		// name of the device
		65536,			// portion of the packet to capture. It doesn't matter in this case 
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", nameDevice.c_str() );
		return 2;
	}

	return 1;
}

int SocketRawProgram::CloseRawSocket() {
	pcap_close(fp);
	return 1;
}

int SocketRawProgram::SendRawPacket(std::string descIp, std::string srcIp, int descPort, int srcPort) {
	
	unsigned char packet[1490];
	memset(packet, 0, sizeof(packet));
	
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
	ipHeader.total_len = htons(sizeof(ipHeader) + sizeof(tcpHeader)); //2 bytes 
	ipHeader.ident = 1;
	ipHeader.frag_and_flags = 0;
	ipHeader.ttl = 60;
	ipHeader.proto = IPPROTO_TCP;
	ipHeader.checksum = 0;
	ipHeader.destIP = ResolveAddress( (char*) descIp.c_str() );
	printf("ip: %s\n", descIp.c_str());
	ipHeader.sourceIP = ResolveAddress( (char*) srcIp.c_str() );

	//tcp header
	tcpHeader.srcPort = htons((unsigned short)srcPort);
	tcpHeader.dstPort = htons((unsigned short)descPort);
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
	psdHeader.length = htons(sizeof(tcpHeader));

	memcpy(packet, &psdHeader, sizeof(psdHeader));
	memcpy(packet + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
	tcpHeader.checksum = CheckSum((unsigned short*)packet, (sizeof(tcpHeader) + sizeof(psdHeader)));

	memset(packet, 0, sizeof(packet));
	memcpy(packet, &ipHeader, sizeof(ipHeader));
	ipHeader.checksum = CheckSum((unsigned short*)packet, sizeof(ipHeader));


	memcpy(packet, &ethHeader, sizeof(ethHeader));
	memcpy(packet + sizeof(ethHeader), &ipHeader, sizeof(ipHeader));
	memcpy(packet + sizeof(ethHeader) + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));

	int sizeP = sizeof(ethHeader) + sizeof(ipHeader) + sizeof(tcpHeader);

	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, sizeP) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}
	return 1;

}

SocketRawProgram::SocketRawProgram() {

}

bool SocketRawProgram::ShowDevices() {
	pcap_if_t* pt;
	char err;
	int iErr = pcap_findalldevs(&pt, &err);
	if (iErr == -1) {
		printf("error: %d\n", err);
	}

	pcap_if_t* ptT;
	int iIdInterface = 1;
	printf("devices are available: ");
	for (ptT = pt; ptT; ptT = ptT->next)
	{
		printf("\n%d: ", iIdInterface++);
		printf("\tdescription: \t%s\n", ptT->description);
		printf("\tname: \t\t%s\n", ptT->name);

	}
	return true;
}

bool SocketRawProgram::LoadConfigFromFile() {
	//load default config from file config.txt
	fstream pFile;
	pFile.open("config.txt");
	if (!pFile.is_open()) {
		cout << "config.txt file doesn't exist" << endl;
		return false;
	}


	string line;
	do {
		getline(pFile, line);
		if (line.find("macDsc=") == 0) {
			char strrMac[18];
			strcpy_s(strrMac, (line.substr(7, line.length() - 7).c_str()));
			memcpy(ethHeader.macDsc, strToEthHdr(strrMac), sizeof(ethHeader.macDsc));
		}
		if (line.find("macSrc=") == 0) {
			char strrMac[18];
			strcpy_s(strrMac, (line.substr(7, line.length() - 7).c_str()));
			memcpy(ethHeader.macSrc, strToEthHdr(strrMac), sizeof(ethHeader.macSrc));
		}
		if (line.find("nameDevice=") == 0) {
			nameDevice = line.substr(11, line.length() - 11);
		}
		if (line.find("delay=") == 0) {
			delay = atoi( line.substr(6, line.length() - 6).c_str() );
		}
	} while (line != "");
}

unsigned long SocketRawProgram::ResolveAddress(char* szHost)
{
	unsigned long ipv4addr;
	inet_pton(AF_INET, szHost, &ipv4addr);
	return ipv4addr;
}

unsigned short SocketRawProgram::CheckSum(unsigned short* buffer, int size)
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

unsigned char* SocketRawProgram::strToEthHdr(char* strMac) {
	unsigned char macAddr[6];
	if (6 == sscanf_s(strMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macAddr[0], &macAddr[1], &macAddr[2], &macAddr[3], &macAddr[4], &macAddr[5])) return macAddr;
	else return 0;
}