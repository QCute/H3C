/*
H3C iNode Client for Linux
date:2015/09/09
Author:QCute
License:GPL
*/
//socket header
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<linux/filter.h>
#include <net/if.h>
#include<netpacket/packet.h>

//EAP Defination
typedef enum  { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 }EAP_CODE;
typedef enum  { IDENTITY = 1, NOTIFICATION = 2, MD5C = 4, SRP = 20 }EAP_TYPE;

//the main socket file description
int sock = 0;
//ipv4 address
unsigned char IP[4] = { 0 };
//ethernet card mac address
unsigned char MAC[6] = { 0 };
//capture device name
char device[16] = { 0 };
//username
char username[16] = { 0 };
//password
char password[16] = { 0 };

/*Algorithm provider*/
#include<stdbool.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>
#include<time.h>
//MD5 algorithm header option
#include"MD5.h"
//if use openssl development library
//#include<openssl/md5.h>
//must link libcrypto libssl
//gcc link option -lcrypto -lssl


/*
Encryption algorithm
*/


/*随机数产生算法(与单个rand相比此算法产生随机数较为均匀)*/
unsigned int Random3()
{
	srand((unsigned)time(0));
	return (unsigned int)((rand() << 17) | (rand() << 3) | (rand()));
}

/*加密算法*/
void XOR(unsigned char data[], unsigned datalen, const char key[], unsigned keylen)
{
	// 使用密钥key[]对数据data[]进行异或加密
	/*（注：该函数也可反向用于解密）*/
	unsigned int	i, j;

	// 先按正序处理一遍
	for (i = 0; i<datalen; i++)
	{
		data[i] ^= key[i%keylen];
	}
	// 再按倒序处理第二遍
	for (i = datalen - 1, j = 0; j<datalen; i--, j++)
	{
		data[i] ^= key[j%keylen];
	}
}

/*客户端版本信息*/
void FillClientVersionArea(unsigned char area[20])
{
	const char H3C_VERSION[16] = "EN\x11V7.00-0102";	// 华为客户端版本号(根据所需自行修改)
	const char H3C_KEY[] = "Oly5D62FaE94W7";		// H3C的固定密钥

	char RandomKey[8 + 1] = { 0 };

	unsigned int random = Random3();			// 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);			// 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); 				//(需调整为网络字节序)
	memcpy(area + 16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

/*Windows版本信息*/
void FillWindowsVersionArea(unsigned char area[])
{
	const unsigned char WinVersion[20] = "170393861";	//Windows版本请不要改变
	const char H3C_KEY[64] = "HuaWei3COM1X";		// H3C的固定密钥
	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

/*Base64加密*/
void FillBase64Area(char area[])
{
	unsigned char version[20] = { 0 };
	/*标准的Base64字符映射表*/
	const char Table[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	// 首先生成20字节加密过的H3C版本号信息
	FillClientVersionArea(version);
	// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
	int i = 0, j = 0;
	unsigned char c1, c2, c3;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Table[(c1 & 0xfc) >> 2];
		area[j++] = Table[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
		area[j++] = Table[((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6)];
		area[j++] = Table[c3 & 0x3f];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Table[(c1 & 0xfc) >> 2];
	area[25] = Table[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
	area[26] = Table[((c2 & 0x0f) << 2)];
	area[27] = '=';
}

/*MD5加密*/
void FillMD5Area(unsigned char digest[], unsigned char id, const char pwd[], const unsigned char srcMD5[])
{
	//信息缓冲区
	unsigned char	msgbuf[128] = { 0 }; 		// msgbuf = 'id'+ 'passwd'' + 'srcMD5''
	//密码长度和信息长度
	short pwdlen = strlen(pwd);
	short msglen = 1 + pwdlen + 16;
	//assert(sizeof(msgbuf) >= msglen);		//可选空间不足断言
	//填充数据
	msgbuf[0] = id;
	memcpy(msgbuf + 1, pwd, pwdlen);
	memcpy(msgbuf + 1 + pwdlen, srcMD5, 16);
	/*计算MD5值*/
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx,msgbuf,msglen);
	MD5_Final(digest,&ctx);
}



/*
Authentication algorithm
*/


/*802.1x authentication*/
/*Start*/
_Bool  SendStartPacket()
{
	//use broadcast active authentication
	const unsigned char start[] =
	{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// broadcast address
		MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5],
		0x88, 0x8E, 0x01, 0x01, 0x00, 0x00,		// protocol head、version、EAP message tyoe、message length
	};

	/*send frame*/
	if(send(sock,start,sizeof(start),0)<0)
	{
		printf("send start packet error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send Start Packet.\n");
	return 0;
}

/*Logoff*/
_Bool SendLogoffPacket()
{
	//use broadcast to logoff
	const unsigned char logoff[] =
	{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// broadcast address
		MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5],
		0x88, 0x8E, 0x01, 0x02, 0x00, 0x00,		// protocol head、version、EAP message tyoe、message length
	};

	/*send frame*/
	if(send(sock,logoff,sizeof(logoff),0)<0)
	{
		printf("send logoff packet error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send Logoff Packet.\n");
	return 0;
}

/*Response Notification*/
_Bool SendResponseNotification(const unsigned char data[])
{
	/*data buffer*/
	unsigned char response[128] = { 0 };
	/*ethernet mac header*/
	memcpy(response, data + 6, 6);
	memcpy(response + 6, data, 6);

	/*802.1x authentication protocol*/
	response[12] = 0x88;				// 802.1 protocol (H)
	response[13] = 0x8E;				// 802.1 protocol (L)
	response[14] = 0x01;				// 802.1X Version 1
	response[15] = 0x00;				// Type=0 (EAP Packet)
	response[16] = 0x00;				// Data Length (H)
	response[17] = 0x1b;				// Data Length (L)

	/*EAPOL extensible authentication protocol*/
	response[18] = (EAP_CODE)RESPONSE;		// Code
	response[19] = 0x01; //data[19];		// ID:0x01
	response[20] = 0x00;				// Data Length (H)
	response[21] = 0x1b;				// Data Length (L)
	response[22] = (EAP_TYPE)NOTIFICATION;		// Type

	/* Notification Data (44 Bytes) */
	/*2+20 bytes Client Version*/
	response[23] = 0x01; 				// type 0x01
	response[24] = 0x16;   				// lenth
	FillClientVersionArea(response + 25);		// Client Version

	/*send*/
	if(send(sock,response,sizeof(response),0)<0)
	{
		printf("send Notification error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send Notification Packet.\n");
	return 0;
}

/*Response Identity*/
_Bool SendResponseIdentity(const unsigned char data[])
{
	/*data buffer*/
	unsigned char response[128] = { 0 };
	/*ethernet header*/
	memcpy(response, data + 6, 6);
	memcpy(response + 6, data, 6);

	/*802.1x authentication protocol*/
	response[12] = 0x88;				// 802.1 protocol (H)
	response[13] = 0x8E;				// 802.1 protocol (L)
	response[14] = 0x01;				// 802.1X Version 1 (2001)
	response[15] = 0x00;				// Type=0 (EAP Packet)
	response[16] = 0x00; 				// Length
	response[17] = 0x2f;

	/*EAPOL extensible authentication protocol*/
	response[18] = (EAP_CODE)RESPONSE;		// Code
	response[19] = 0x02; // data[19];		// ID:0x02
	response[20] = 0x00; 				// Length
	response[21] = 0x2f;
	response[22] = (EAP_TYPE)IDENTITY;		// Type

	/*EAP type data*/
	response[23] = 0x06;	  			// upload IP address
	response[24] = 0x07;
	FillBase64Area((char*)response + 25);		// Base64 encryption
	/*add tow space*/
	response[53] = response[54] = 0x20;
	/*add username on the end*/
	memcpy(response + 55, username, 10);

	/*send*/
	if(send(sock,response,sizeof(response),0)<0)
	{
		printf("send Identity error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send Identity Packet.\n");
	return 0;
}

/*Response MD5-Challenge EAP (EAP-MD5-CHALLENGE)*/
_Bool SendResponseMD5(const unsigned char data[])
{
	/*data buffer*/
	unsigned char  response[128] = { 0 };
	/*ethernet header*/
	memcpy(response, data + 6, 6);
	memcpy(response + 6, data, 6);

	/*802.1x authentication protocol*/
	response[12] = 0x88;					// 802.1 protocol H
	response[13] = 0x8E;					// 802.1 protocol L
	response[14] = 0x01;					// 802.1X Version 1
	response[15] = 0x00;					// Type=0 (EAP Packet)
	response[16] = 0x00;  					// Length (H)
	response[17] = 0x20;					// Length (L) (10 bytes(username)+22 bytes(ahead data))

	/*EAPOL extensible authentication protocol*/
	response[18] = (EAP_CODE)RESPONSE;			// Code
	response[19] = 0x03; //data[19];			// ID:0x03
	response[20] = response[16];				// Length H
	response[21] = response[17];				// Length L
	response[22] = (EAP_TYPE)MD5C;				// Type
	response[23] = 0x10;					// Value-Size: 16 Bytes
	FillMD5Area(response + 24, data[19], password, data + 24);//MD5 area
	memcpy(response + 40, username, 10);

	/*send*/
	if(send(sock,response,sizeof(response),0)<0)
	{
		printf("send MD5 error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send MD5 Packet.\n");
	return 0;
}

/*Response Secure Remote Password SHA1 Part 2 EAP (EAP-SRP-SHA1-PART2)*/
_Bool SendResponseSRP(const unsigned char data[])
{
	/*data buffer*/
	unsigned char  response[128] = { 0 };
	/*ethernet header*/
	memcpy(response, data + 6, 6);
	memcpy(response + 6, data, 6);

	/*802.1x authentication protocol*/
	response[12] = 0x88;				// 802.1 protocol (H)
	response[13] = 0x8E;				// 802.1 protocol (L)
	response[14] = 0x01;				// 802.1X Version 1
	response[15] = 0x00;				// Type=0 (EAP Packet)
	response[16] = 0x00;				// Lenght
	response[17] = 0x36;				// 88 bytes

	/*EAP data length 88 bytes*/
	/*EAPOL extensible authentication protocol*/
	response[18] = (EAP_CODE)RESPONSE;		// Code
	response[19] = data[19];			// ID:count
	response[20] = response[16];			// Length H
	response[21] = response[17];			// Length L
	response[22] = (EAP_TYPE)SRP;			// Type 0x14
	response[23] = 0x00;				// Reported whether the use of agents
	response[24] = 0x15;				// upload IP address
	response[25] = 0x04;

	memcpy(response + 26, IP, 4);			// IPv4 address
	response[30] = 0x06;				// carry version
	response[31] = 0x07;
	FillBase64Area((char*)(response + 32));		// 28 bytes Base64 encryption
	response[60] = response[61] = 0x20;		// tow space
	memcpy(response + 62, username, 10);		// username

	/*send*/
	if(send(sock,response,sizeof(response),0)<0)
	{
		printf("send SRP error !%s\n",strerror(errno));
		return 1;
	};
	printf("Send SRP Packet.\n");
	return 0;
}

/*Count Array Size*/
#ifdef ARRAY_SIZE
#else
#define ARRAY_SIZE(array) (int)(sizeof(array)/sizeof(array[0]))
#endif

/*Do Initialize before start authenticate*/
_Bool Initialize()
{
    ///use raw socket to receive the ethernet packet
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) 
    {
		printf("create socket error !%s\n",strerror(errno));
		return 1;
    }

    /**set and get ethernet card option**/
    struct ifreq ifr;
    ///initialize device name
    strncpy(ifr.ifr_name,device,IFNAMSIZ);

    ///check net work is runing or not
    if (ioctl(sock,SIOCGIFFLAGS,&ifr)<0) 
    {
		close(sock);
		printf("IO error !%s\n",strerror(errno));
		return 1;
    }

    if(!(ifr.ifr_flags&IFF_RUNNING))
    {
		close(sock);
		printf("network is down!\n");
		return 1;
    }

    ///close promsic mode(increase netcard io performance)
    ifr.ifr_flags ^= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr)<0)
    {
		close(sock);
		printf("IO error !%s\n",strerror(errno));
		return 1;
    }

    ///get hard ware address(MAC address)
    if (ioctl(sock,SIOCGIFHWADDR,&ifr)<0) 
    {
		close(sock);
		printf("IO error !%s\n",strerror(errno));
		return 1;
    }
    memcpy(MAC,(ifr.ifr_hwaddr.sa_data),ETH_ALEN);

    ///get netcard name index(OR use if_nametoindex function to get index)
    if (ioctl(sock,SIOCGIFINDEX,&ifr)<0) 
    {
		close(sock);
		printf("IO error !%s\n",strerror(errno));
		return 1;
    }


    /**bind devices**/
    struct sockaddr_ll addr;
    addr.sll_family = PF_PACKET;
    addr.sll_ifindex=ifr.ifr_ifindex;
    memcpy(addr.sll_addr,&(ifr.ifr_hwaddr),ETH_ALEN);
    //bind net card(use specify netcard to send/receive data)
    if (bind(sock,(struct sockaddr*)&addr,sizeof(addr)) < 0) 
    {
		close(sock);
		printf("bind netcard error !%s\n",strerror(errno));
		return 1;
    }


    /**set the bpf filter to the kernel**/
    //if the bpf code not correct  the setsockopt return -1 and error is invalid argument
    //this bpf code be use to filter 0x880E type of the ethernet packet and return 256 bytes
    struct sock_filter bpf_code[]= 
    {
	    BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
	    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,0x888E,0,1),
	    BPF_STMT(BPF_RET+BPF_K,256),
	    BPF_STMT(BPF_RET+BPF_K,0)
    };
    //fill socket filter struct
    struct sock_fprog bpf_filter;
    bpf_filter.filter = bpf_code;
    bpf_filter.len = ARRAY_SIZE(bpf_code);
    ///atach filter to kernel
    if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&bpf_filter,sizeof(bpf_filter)))
    {
		close(sock);
		printf("set socket option(atach filter) error !%s\n",strerror(errno));
		return 1;
    }

    //set all option(initialize) success and return 0(no error)
    return 0;
}

void CapturePacket(void)
{
    ///do initialize
    if(Initialize())return;
    ///start
    if(SendStartPacket())
    {
	    close(sock);
	    return;
    };

    ///receive packet buffer
    unsigned char packet_data[256] = {0};

    ///dead loop(if want to break it,please use killall command to kill it)
    while(1)
    {
        recv(sock,packet_data,sizeof(packet_data),0);
        //analyze packet
        switch ((EAP_CODE)packet_data[18])
		{
		case REQUEST:
		{
			switch ((EAP_TYPE)packet_data[22])
			{
			case IDENTITY:
			if(SendResponseIdentity(packet_data))
			{
				close(sock);
				return;
			}; break;
			case NOTIFICATION:
			if(SendResponseNotification(packet_data))
			{
				close(sock);
				return;
			}; break;
			case MD5C:
			if(SendResponseMD5(packet_data))
			{
				close(sock);
				return;
			}; break;
			case SRP:
			if(SendResponseSRP(packet_data))
			{
				close(sock);
				return;
			}; break;
			default:break;
			}
		}break;
		//case RESPONSE:break;///this item not use(base on iNode 7.0)
		//print authenticate sucess message
		case SUCCESS:
		{
			printf("Authentication Success!\n");
		}break;
		//print error message when authenticate failed
		case FAILURE:
		{
			printf("Authentication Failed!   %s\n\n\n",packet_data+32);close(sock);
			return;
		}break;
		//cover h3c message (if you want yo show it,you can print it to the console)
		case H3CDATA:{}break;
		default:break;
		}
    }
    //end of function
    return;
}
