#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
// #include <regex.h>
#include "header.h"

//#define MYIP "ifconfig ens33 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'"


unsigned short check_sum ( unsigned short* buffer, int len );
void parsing (char* mode, char* output);
void event_handle (int sd, const u_char *data, struct ETH *neweth, struct IP *newip, struct TCP *newtcp);
void rtrim (char* input, char* output);

int main ( void ) {
	signal(SIGPIPE, SIG_IGN); // broken pipe 오류 방지

	pcap_t *pcd;
	struct bpf_program bpf;
	char *device = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *pkt_header;
	char *rule;
	char myip[16] = {0};
	char *imsi;
	const u_char *pkt_data;
	int trash, sd, res;

	struct ETH *neweth = malloc(sizeof(neweth));
	struct IP *newip = malloc(sizeof(newip));
	struct TCP *newtcp = malloc(sizeof(newtcp));

	//parsing(MYIP, myip);
	//rtrim(myip, imsi);
	//sprintf(rule, "host {%s} && {tcp port 80}", imsi);
	//printf("%s",rule);

	if ((sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("socket failed");
		return 1;
	}
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&trash, sizeof(trash));

	device = pcap_lookupdev(errbuf);
	if (!device) {
		fputs(errbuf, stderr);
		return 1;
	}
	pcd = pcap_open_live(device, 1500, 1, -1, errbuf); // promiscous mode 
	if (!pcd) {
		fputs(errbuf, stderr);
		return 1;
	}

	// promiscous 모드인데 모든 ip 대역을 대상으로 하면 피해를 끼칠 수 있으므로 자기 자신 ip로 하겠습니다.
	if ( pcap_set_datalink ( pcd, DLT_EN10MB )) return 1; // capture ethernet packet
	if ( pcap_compile ( pcd, &bpf, "src host 192.168.32.37 && tcp port 80", 0, PCAP_NETMASK_UNKNOWN ) == -1 ) return 1; // capture http packet
	if ( pcap_setfilter ( pcd, &bpf ) == -1 ) return 1; // configuration

	while((res = pcap_next_ex(pcd, &pkt_header, &pkt_data)) >= 0) {
 		if (res == 0)
 			continue;
 		event_handle(sd, pkt_data, neweth, newip, newtcp);
 	}

	pcap_close(pcd);
	return 0;
}

void event_handle (int sd, const u_char *data, struct ETH *neweth, struct IP *newip, struct TCP *newtcp)
{
	const char redirect[] = "HTTP/1.1 302 Found\\r\\nLocation: http://warning.or.kr/ ";
	struct ETH *ethh; // eth header config
	struct IP *iph; // ip header config
	struct TCP *tcph; // tcp header config
	size_t size_ipdata, size_tcpdata;

	unsigned short ip_ck, tcp_ck; // 먼저 다 입력을 하고 체크섬을 구해야 함.

	// 14(ETH) + 20(IP) + 20(TCP) + string 길이(54) = 108
	unsigned char send_data[108] = {0};
	
	ethh = (struct ETH *)data;
	data += sizeof(struct ETH); // sum eth len
	iph = (struct IP *)data;
	data += (IP_HL(iph))*4; // sum ip len
	tcph = (struct TCP *)data;
	data += (TH_OFF(tcph))*4; // sum tcp len

	size_ipdata = 20 + 20 + strlen(redirect); // ip 기본 헤더 + tcp 기본 헤더 + 문자열 길이
	size_tcpdata = 20 + strlen(redirect); // tcp 기본 헤더 + 문자열 길이

	/* 너무 느릴 꺼 같아 버린 버전. 메모리 입출력을 줄이는 방법 생각 */
	// if(!strncmp (data ,"GET", size_tcpdata)) {
	// 	// data 수정 해서 버퍼에 담기
	// 	memcpy(send_data, data, 108); // 초기화
	// 	memcpy(send_data, ethh->ether_shost, 6); // 송신자와 수신자 물리주소 바꾸기
	// 	memcpy(send_data+6, ethh->ether_dhost, 6);
	// 	memcpy(send_data+14, "\x45", 1); // IP 헤더 길이 고정
	// 	memcpy(send_data+16, "\x00\x5E", 2); // IP 전체 길이 고정
	// 	memcpy(send_data+20, "\x40\x00", 2); // don't fragment flag 설정
	// 	memcpy(send_data+22, "\x7D", 1); // 패킷이 죽을 수 있으므로 ttl 125로 초기화
	// 	memcpy(send_data+24, "",2); // ip checksum 계산
	// 	for (int i=0;i<108;i++)
	// 		printf("%02hhX",*(send_data+i));
	// 	printf("\n");
	// }
	struct sockaddr_ll dev;

	memset(&dev, 0 , sizeof(dev));
	dev.sll_family = AF_INET;
	dev.sll_ifindex = if_nametoindex("ens33");
	//dev.sll_halen = ETH_ALEN;
	//memcpy(&dev.sll_addr, &ethh->dhost1, 6);

	memcpy(send_data, &ethh->shost1, 6); // 송신자와 수신자 물리주소 바꾸기
	memcpy(send_data+6, &ethh->dhost1, 6);
	send_data[12] = '\x08'; // ip 패킷만 설정
	
	newip->ip_vhl = '\x45'; // ipv4, 기본 20 byte 설정
	newip->ip_tos = '\x00';
	newip->ip_len = ntohs((uint16_t) size_ipdata); // ip 전체 길이 계산
	newip->ip_id = iph->ip_id;
	newip->ip_off = '\x00\x40'; // 작은 패킷이므로 don't flag 설정 ( 빅엔디안 이므로 리틀 엔디안으로 변경 )
	newip->ip_ttl = '\x7D'; // 패킷이 죽을 수 있으므로 ttl 125로 초기화 
	newip->ip_p = '\x06'; // tcp 패킷만 적용
	newip->ip_sum = '\x00';
	newip->ip_src = iph->ip_dst; // 송신자와 수신자 ip주소 바꾸기
	newip->ip_dst = iph->ip_src;

	newtcp->th_sport = tcph->th_dport; // 송신자와 수신자 port 바꾸기
	newtcp->th_dport = tcph->th_sport;
	newtcp->th_seq = tcph->th_ack + (iph->ip_len-IP_HL(iph)-TH_OFF(tcph)); // 송신자와 수신자가 seq ack 바꾸고 계산
	newtcp->th_ack = tcph->th_seq;
	newtcp->th_offx2 = '\x14'; // 20 바이트 고정
	newtcp->th_flags = TH_FIN; //
	newtcp->th_win = tcph->th_win; // 그대로 써도 알아서 tcp window 크기 조절
	newtcp->th_sum = '\x00';
	newtcp->th_urp = '\x00\x00';

 	memcpy(send_data+34, newtcp, 20); // tcp 헤더 셋팅 
 	memcpy(send_data+54, redirect, strlen(redirect)); // tcp 데이터 셋팅
 	newtcp->th_sum = check_sum((unsigned short *)send_data+34, (20+strlen(redirect))/sizeof(unsigned short)); // checksum 구조체에 담기
 	memcpy(send_data+50, &newtcp->th_sum, 2); //계산 한 checksum 다시 셋팅

 	memcpy(send_data+14, newip, 20); // ip 헤더 셋팅
 	newip->ip_sum = check_sum((unsigned short *)send_data+14, (20+20+strlen(redirect))/sizeof(unsigned short));
 	memcpy(send_data+24, &newip->ip_sum, 2);
	
	printf("[*] Send Blocked Packet\n");
	for (int i=0;i<108;i++)
		printf("%02hhX",*(send_data+i));
	printf("\n");

 	if (sendto(sd, send_data, 108, 0, (struct sockaddr *)&dev, sizeof(dev)) < 0)
 	{
 		perror("sendto error");
 		return 1;
 	}
}

void parsing (char* mode, char* output)
{
        char line[16] = {0};
        FILE *fp = popen(mode,"r");
        fgets(line, sizeof(line)-1, fp);
        output = line;
}
// ip , tcp 체크섬 구할 때 16비트로 더함.
unsigned short check_sum ( unsigned short* buffer, int len )
{
	/* 버퍼읽고 합쳐서 캐리 더하고 1의 보수 취한다 */
	unsigned int sum = 0; // int type 인자로 준 이유는 오버플로우
	for ( sum=0; len>0; len-- )
		sum += *buffer++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) ~sum;
}


// 공백을 제거하기 위한 함수
// void rtrim (char* input, char* output)
// {
// 	int len = strlen(input);
// 	int r_size=0, cnt=0;
// 	for(int i=len-1;i>=0;i--) {
// 		if(*(input+i)!=' ') {
// 			r_size=cnt;
// 			break;
// 		}
// 		cnt++;
// 	}
// 	r_size=len-cnt;
// 	len=r_size;
// 	memset(output,'\0',sizeof(output));
// 	for(int i=0;i<len;i++)	{
// 		output[i]=*(input+i);
// 	}
// }
