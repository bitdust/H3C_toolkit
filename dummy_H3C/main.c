#define _CRT_SECURE_NO_WARNINGS //不在提示关于 strcpy() memcpy() 等函数的警告

#include "pcap.h"
#include <windows.h>

// from njit8021xclient project
#define START 1
#define REQUEST 1
#define RESPONSE 2
#define SUCCESS 3
#define FAILURE 4
#define H3CDATA 10

#define IDENTITY 1
#define NOTIFICATION 2
#define MD5 4
#define AVAILABLE 20 u
typedef UINT8 EAP_ID;
const UINT8 BroadcastAddr[6]	= {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const UINT8 MultcastAddr[6]	= {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址

int loop(const  char *DeviceName); 
void SendRequestIdentity(pcap_t *handle,const UINT8 ethhdr[]); 
void SendRequestMD5(pcap_t *handle,const UINT8 MAC[6]); 
void SendSuccess(pcap_t *handle,const UINT8 MAC[6]); 
void SendH3C(pcap_t *handle,const UINT8 MAC[6]); 
void RecvStart(pcap_t *handle,const UINT8 MAC[6]); 
void RecvResponse(pcap_t *handle,const UINT8 MAC[6]); 
void RecvResponseMD5(pcap_t *handle,const UINT8 MAC[6]); 

int main()
{
	char *UserName = NULL;
	char *Password = NULL;
	char *DeviceName = NULL;
	char buf[256];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	char key;
	if (pcap_findalldevs(&alldevs,errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
	}
	printf("Select an adapter by input Y\n");
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{
		printf("%s (%s)\n", dev->name, dev->description);
		key = getchar();
		if (key == 'Y' || key == 'y')
		{
			strcpy(buf, dev->name);
			DeviceName = buf;
			break;
		}
	}
	pcap_freealldevs(alldevs);
	loop(DeviceName);
	return 1;
}

int loop(const  char *DeviceName)
{
	int retcode;
	struct pcap_pkthdr *header = NULL;
	UINT8	*captured = NULL;
	UINT8   ethhdr[14]={0};
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*handle; // adapter handle
	UINT8	MAC[6]={0x0c,0xda,0x41,0x97,0xd9,0x10};
	char	FilterStr[100];
	//char	infobuf[100];
	char serverIsFound = 0;
	FILE	*fpinfo = NULL;
	struct bpf_program	fcode;
	const int DefaultTimeout = 500;			//60000;//设置接收超时参数，单位ms	
	/** 打开网卡 **/
	handle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		return -1;
	}
	/** 设置过滤器监听多播/广播地址 **/
	sprintf(FilterStr,"(ether dst host 0c:da:41:97:d9:10 ) or (ether dst host %02x:%02x:%02x:%02x:%02x:%02x) or (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",BroadcastAddr[0],BroadcastAddr[1],BroadcastAddr[2],BroadcastAddr[3],BroadcastAddr[4],BroadcastAddr[5],MultcastAddr[0],MultcastAddr[1],MultcastAddr[2],MultcastAddr[3],MultcastAddr[4],MultcastAddr[5]);
	pcap_compile(handle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(handle, &fcode);
	/** 等待客户端发起接入 **/
	while (!serverIsFound)
	{
		retcode = pcap_next_ex(handle, &header, &captured);
		if (retcode==1 && /*(EAP_Code)*/captured[15]==START)
			serverIsFound = 1;
		else
		{	
			printf(".");
		}
	}
	printf("client connected.");

	memcpy(ethhdr+0,captured+6,6);
	memcpy(ethhdr+6,MAC,6);
	ethhdr[12] = 0x88;
	ethhdr[13] = 0x8e;
	SendRequestIdentity(handle,ethhdr);
	return 1;
}

void SendRequestIdentity(pcap_t *handle,const UINT8 ethhdr[])
{
	UINT8 packet[77];
	memset(packet,0,sizeof(UINT8)*77);
	memcpy(packet,ethhdr,14);
	packet[14] = 0x01; // 802.1x version 1
	packet[15] = 0x00; // EAP Packet
	/** 16~17 为802.1x长度 **/
	packet[16] = 0x00;
	packet[17] = 0x05;
	packet[18] = REQUEST;
	packet[19] = 1; // Id
	/** 20~21 为EAP包长度 **/
	packet[20] = 0x00;
	packet[21] = 0x05;
	packet[22] = 1; // Type:Identity
	pcap_sendpacket(handle, packet, sizeof(packet)); //错误的FCS
}
