#include <stdio.h>
#include <stdlib.h>
#include <io.h>





#define alt_8    char
#define alt_u8   unsigned char
#define alt_32   int
#define alt_u32  unsigned int
#define alt_64   long long
#define alt_u64  unsigned long long

extern int crc32_test();
extern alt_u32 Reverse_Table_CRC(alt_u8 *data, alt_32 len);


//位翻转函数
alt_u64 Reflect(alt_u64 ref,alt_u8 ch)
{	
	int i;
	alt_u64 value = 0;
	for( i = 1; i < ( ch + 1 ); i++ )
	{
		if( ref & 1 )
			value |= 1 << ( ch - i );
		ref >>= 1;
	}
	return value;
}


//标准的CRC32多项式
#define poly  0x04C11DB7
//翻转的CRC32多项式
#define upoly 0xEDB88320

alt_u32 Table[256];

// 生成CRC32 翻转表 第二项是77073096
void gen_normal_table(alt_u32 *table)
{
	alt_u32 gx = 0x04c11db7;
	alt_u32 temp,crc;
	int i,j;
	for(i = 0; i <= 0xFF; i++) 
	{
		temp=Reflect(i, 8);
		table[i]= temp<< 24;
		for (j = 0; j < 8; j++)
		{
			unsigned long int t1,t2;
			unsigned long int flag=table[i]&0x80000000;
			t1=(table[i] << 1);
			if(flag==0)
				t2=0;
			else
				t2=gx;
			table[i] =t1^t2 ;
		}
		crc=table[i];
		table[i] = Reflect(table[i], 32);
	}
}




alt_u32 Reverse_Table_CRC(alt_u8 *data, alt_32 len)
{
	alt_u32 crc = 0xffffffff;  
	alt_u8 *p = data;
	int i;
	//生成翻转表，是官方推荐的，故称其为normal_table
	gen_normal_table(Table);
	for(i=0; i <len; i++)
		crc =  Table[( crc ^( *(p+i)) ) & 0xff] ^ (crc >> 8);
	return  ~crc ; 
}



//这是一个完整的以太网帧。最后四个字节 8b 6b f5 13是其FCS字段，用于与后面生成的CRC32对照
alt_u8  tx_data[] = {
	0xff,   0xff,   0xff,   0xff,   0xff,   0xff,   0x00,   0x1f,   //8
	0x29,   0x00,   0xb5,   0xfa,   0x08,   0x06,   0x00,   0x01,   //15
	0x08,   0x00,   0x06,   0x04,   0x00,   0x01,   0x00,   0x1f,   //24
	0x29,   0x00,   0xb5,   0xfa,   0xac,   0x15,   0x0e,   0xd9,   //32
	0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0xac,   0x15,   //40
	0x0e,   0x8e,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   //48
	0x00,   0x00 ,  0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   //56
	0x00,   0x00,   0x00,   0x00,   0x8b,   0x6b,   0xf5,   0x13    //64
};




int crc32_test()
{
	alt_u8 *data = tx_data;
	alt_u8 dataLen = sizeof(tx_data) -4;

	int sum = 256;
	int i = 0;


	printf("Table :\n");
	for(i = 0; i < sum; i++)
	{
		if(i<16)
			printf("0x%08x,",Table[i]);
	}
	printf("\n\n");



	printf("dataLen = %d\n",dataLen);//打印数据长度，应该是60字节。



	//计算并打印出CRC32校验码，应该是0x13f56b8b
	//使用翻转表，官方推荐的，很快
	printf("Reverse Table  ref + xor : %08x\n",Reverse_Table_CRC(data,dataLen)); 

	system("pause");    
	return 0;
}
