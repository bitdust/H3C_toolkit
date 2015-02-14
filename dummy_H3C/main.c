#include "pcap.h"

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

int main()
{

}