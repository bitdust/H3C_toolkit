#define _CRT_SECURE_NO_WARNINGS //不在提示关于 strcpy() memcpy() 等函数的警告

#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <windows.h>

//code from njit8021xclient project
#define START 1
#define REQUEST 1
#define RESPONSE 2
#define SUCCESS 3
#define FAILURE 4
#define H3CDATA 10

#define IDENTITY 1
#define NOTIFICATION 2
#define MD5 4
#define AVAILABLE 20
typedef UINT8 EAP_ID;
const UINT8 BroadcastAddr[6]	= {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const UINT8 MultcastAddr[6]	= {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址

int loop(const  char *DeviceName); 
void SendRequestIdentity(pcap_t *handle,const UINT8 ethhdr[]); 
void SendRequestMD5(pcap_t *handle,const UINT8 ethhdr[]); 
void SendSuccess(pcap_t *handle,const UINT8 ethhdr[]); 
void SendH3C(pcap_t *handle,const UINT8 ethhdr[]); 
//void RecvStart(pcap_t *handle); 
void RecvResponse(pcap_t *handle); 
//void RecvResponseMD5(pcap_t *handle); 

// from crc32.c
extern int crc32_test();
extern unsigned int Reverse_Table_CRC(unsigned int *data, unsigned int len);

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
	printf("输入 Y 选择网卡，按下 Enter 显示下一网卡\n");
	printf("使用说明见：https://github.com/bitdust/H3C_toolkit \n\n");
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
	return 0;
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
	char	FilterStr[200];
	//char	infobuf[100];
	char clientIsFound = 0;
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
	printf("\nWaiting for client\n");
	while (!clientIsFound)
	{
		retcode = pcap_next_ex(handle, &header, &captured);
		if (retcode==1 && /*(EAP_Code)*/captured[15]==START)
			clientIsFound = 1;
		else
		{	
			printf(".");
		}
	}
	printf("\nclient connected.\n");

	memcpy(ethhdr+0,captured+6,6);
	memcpy(ethhdr+6,MAC,6);
	ethhdr[12] = 0x88;
	ethhdr[13] = 0x8e;

	// 发送请求
	SendRequestIdentity(handle,ethhdr);

	// 接收回复
	RecvResponse(handle);

	// 发送MD5请求
	SendRequestMD5(handle,ethhdr);

	// 接收回复
	RecvResponse(handle);

	// 发送认证成功消息
	SendSuccess(handle,ethhdr);

	// 发送H3C定制的消息
	printf("press Enter to send H3C information.\n");
	getchar();
	getchar();
	SendH3C(handle,ethhdr);

	// 发送请求
	printf("press Enter to send request identity.\n");
	getchar();
	SendRequestIdentity(handle, ethhdr);

	printf("press Enter to exit.\n");
	getchar();
	return 0;
}

void SendRequestIdentity(pcap_t *handle,const UINT8 ethhdr[])
{
	UINT8 packet[77];
	unsigned int fcs; 
	memset(packet,0,sizeof(packet));
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
	fcs = Reverse_Table_CRC((unsigned int *)&packet,sizeof(packet)-4);
	memcpy(&packet[sizeof(packet)-4],&fcs,sizeof(fcs)); // fill the FCS field
	pcap_sendpacket(handle, packet, sizeof(packet));
}

void RecvResponse(pcap_t *handle)
{
	int retcode;
	struct pcap_pkthdr *header = NULL;
	UINT8	*captured = NULL;
	int responseIsReceived = 0;
	printf("waiting for EAP response.\n");
	while (!responseIsReceived)
	{
		retcode = pcap_next_ex(handle, &header, &captured);
		if (retcode==1 && /*(EAP_Code)*/captured[15]== 0 &&captured[12]==0x88 &&captured[13] == 0x8e && captured[18] == RESPONSE)
			responseIsReceived = 1;
		else
		{	
			printf(".");
		}
	}
	printf("\nEAP response received.\n");
}

void SendRequestMD5(pcap_t *handle,const UINT8 ethhdr[])
{
	UINT8 packet[64];
	unsigned int fcs; 
	memset(packet,0,sizeof(packet));
	memcpy(packet,ethhdr,14);
	packet[14] = 0x01; // 802.1x version 1
	packet[15] = 0x00; // EAP Packet
	/** 16~17 为802.1x长度 **/
	packet[16] = 0x00;
	packet[17] = 0x16;
	packet[18] = REQUEST;
	packet[19] = 2; // Id
	/** 20~21 为EAP包长度 **/
	packet[20] = 0x00;
	packet[21] = 0x16;
	packet[22] = MD5; // Type:EAP-MD5-CHALLENGE
	packet[23] = 16;// eap.md5.value_size
	/** 24~40 为MD5码值，暂为全零 **/
	fcs = Reverse_Table_CRC((unsigned int *)&packet,sizeof(packet)-4);
	memcpy(&packet[sizeof(packet)-4],&fcs,sizeof(fcs)); // fill the FCS field
	pcap_sendpacket(handle, packet, sizeof(packet));
}

void SendSuccess(pcap_t *handle,const UINT8 ethhdr[])
{
	UINT8 packet[64];
	unsigned int fcs; 
	memset(packet,0,sizeof(packet));
	memcpy(packet,ethhdr,14);
	packet[14] = 0x01; // 802.1x version 1
	packet[15] = 0x00; // EAP Packet
	/** 16~17 为802.1x长度 **/
	packet[16] = 0x00;
	packet[17] = 0x04;
	packet[18] = 0x03; //SUCCESS
	packet[19] = 2; // Id
	/** 20~21 为EAP包长度 **/
	packet[20] = 0x00;
	packet[21] = 0x04;
	fcs = Reverse_Table_CRC((unsigned int *)&packet,sizeof(packet)-4);
	memcpy(&packet[sizeof(packet)-4],&fcs,sizeof(fcs)); // fill the FCS field
	pcap_sendpacket(handle, packet, sizeof(packet));
}

// 发送类型为0x0A的802.1x信息
void SendH3C(pcap_t *handle,const UINT8 ethhdr[])
{
	//UINT8 aes_data[32] = { 0x16, 0x4c, 0x81, 0xf2, 0xcb, 0x49, 0x21, 0x2e, 0x68, 0x34, 0xfb, 0xdd, 0xbe, 0xe8, 0x5a, 0xf3, 0xd6, 0x81, 0xf4, 0x43, 0x36, 0x09, 0xc1, 0x62, 0xb1, 0x52, 0x57, 0x99, 0xe3, 0x45, 0x80, 0xc7 };
	//UINT8 aes_data[32] = { 0x42, 0x04, 0x20, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	// should return 667b928032f749728cd4c5e323f95a440fada507573e62a6bd2a7bcbee99a993
	// UINT8 aes_data[32] = { 0xcf, 0xfe, 0x64, 0x73, 0xd5, 0x73, 0x3b, 0x1f, 0x9e, 0x9a, 0xee, 0x1a, 0x6b, 0x76, 0x47, 0xc8, 0x9e, 0x27, 0xc8, 0x92, 0x25, 0x78, 0xc4, 0xc8, 0x27, 0x03, 0x34, 0x50, 0xb6, 0x10, 0xb8, 0x35 };
	// should return 8719362833108a6e16b08e33943601542511372d8d1fb1ab31aa17059118a6ba from zhaoban02
	UINT8 aes_data[32] = { 0xd8, 0xb9, 0x6e, 0x50, 0xc0, 0xdc, 0x5a, 0x4b, 0x70, 0x65, 0x22, 0xca, 0x6a, 0xdc, 0x7b, 0x15, 0xd6, 0x7f, 0xf9, 0x52, 0x9c, 0xd2, 0x77, 0xe7, 0x3c, 0x02, 0xc1, 0x3e, 0x12, 0x0e, 0xf3, 0x42 };
	// should return 6e08e837e09ec58c988ac35e3ec322b55e95b996a5cc7644c79536320f3a1495  (2016621E0313dictsample)
	UINT8 packet[77];
	unsigned int fcs; 
	memset(packet,0,sizeof(packet));
	memcpy(packet,ethhdr,14);
	packet[14] = 0x01; // 802.1x version 1
	packet[15] = 0x00; // EAP Packet
	/** 16~17 为802.1x长度 **/
	packet[16] = 0x00;
	packet[17] = 0x37;
	packet[18] = 0x0a; //H3C code
	packet[19] = 3; // Id
	/** 20~21 为EAP包长度 **/
	packet[20] = 0x00;
	packet[21] = 0x37;
	packet[22] = 0x19;
	packet[23] = 0x2b;
	packet[24] = 0x44;
	packet[25] = 0x2b;
	packet[26] = 0x35;
	memcpy(packet + 27 * sizeof(UINT8), &aes_data, 32);
	fcs = Reverse_Table_CRC((unsigned int *)&packet,sizeof(packet)-4);
	memcpy(&packet[sizeof(packet)-4],&fcs,sizeof(fcs)); // fill the FCS field
	pcap_sendpacket(handle, packet, sizeof(packet));
}