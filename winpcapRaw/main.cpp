#define WIN32_LEAN_AND_MEAN
#define WIN32

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

#include <stdlib.h>
#include <stdio.h>
#include <string>

#include <pcap.h>

#include "SocketRawProgram.h"

using namespace std;


int main(int argc, char** argv)
{
	string arg = argv[1];
	if (arg == "-h" || (argc == 3 ) ) {
		printf("Usage: rawSock [option] [Descination IP] [Source IP] [Descination Port] [Source Port] \n");
		printf("  -h\t\t- help \n");
		printf("  -l\t\t- repeat sending packets; example: -l 50 \n");
		printf("  -rSIp\t\t- random Source Ip \n");
		printf("  -rSIpL\t\t- random Source Ip - only last byte \n");
		printf("  -rSP\t\t- random Source Port \n");
	}
	int portS = 45678;
	int postD = 80;
	string ipS = "195.50.7.181";
	string ipD = "95.173.136.168";
	
	bool help = false;
	bool loop = false;
	int lLoop = 0;
	bool randSrcIp = false;
	bool randSrcPort = false;
	bool randLastByteSrcIp = false;

	for (int i = 0; i < argc; i++ ) {
		arg = argv[i];
		if (arg == "-h") help = true;
		if (arg == "-l") {
			loop = true;
			lLoop = atoi(argv[i + 1]);
		} 
		if (arg == "-rSIp") randSrcIp = true;
		if (arg == "-rSIp") randSrcIp = true;
		if (arg == "-rSIpL") randLastByteSrcIp = true;
	}

	if (argc > 4) {
	int portS = atoi(argv[argc-1]);
	int portD = atoi(argv[argc-2]);
	ipS = argv[argc-3];
	ipD = argv[argc-4];
	
	SocketRawProgram* sockRaw = new SocketRawProgram();
	sockRaw->InitRawSocket();
	sockRaw->LoadConfigFromFile();

	arg = argv[1];
	if (loop) {
		lLoop = atoi(argv[2]);
		for (int i = 0; i < loop; i++) {
			sockRaw->SendRawPacket(ipD.c_str(), ipS.c_str(), portD, portS);
			Sleep(sockRaw->delay);
		}
	}
	else {
		sockRaw->SendRawPacket(ipD.c_str(), ipS.c_str(), portD, portS);
		}	


	sockRaw->CloseRawSocket();
	}
	
	return 1;
}