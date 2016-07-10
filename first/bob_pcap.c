#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unistd.h>

#define PROMISC 1
#define NONPROMISC 0


#define IPV4 0x0800
#define IPV6 0x86DD
#define TCP 0x06
#define UDP 0x11

void callback (u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet ) {

	const uint16_t eth_pro_flag = (packet[12] << 8) | packet[13];
	printf("=========================\n");
	printf("dst_mac : %02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
	printf("src_mac : %02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
	
	if ( eth_pro_flag == IPV4 )
	{
		const uint8_t *ip_packet = (uint8_t *)packet+14;
		int ihl = (ip_packet[0] & 0x0f)*4; // IP 패킷 길이
		ihl = ihl+(ihl%20); // TCP 패킷 길이 구하기 위한 IP 패킷길이 값 수정
		const uint8_t ip_pro_flag = ip_packet[9];
		printf("src ip : %d.%d.%d.%d\n" , ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
		printf("dst ip : %d.%d.%d.%d\n" , ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
		
		if ( ip_pro_flag == TCP )
		{
			if ( ihl < 20 )
				printf("비정상적인 IP 패킷입니다."); // 해커가 IP 패킷을 최소길이보다 작게 하는 경우 잘못된 주소 값을 참조하게 될 수 있어서 예외처리 해줍니다.
			const uint8_t *tcp_packet = (uint8_t *)(ip_packet+ihl);
			const uint16_t src_port = (tcp_packet[0]<<8)|tcp_packet[1];
			const uint16_t dst_port = (tcp_packet[2]<<8)|tcp_packet[3];
			printf("src port : %d\n",src_port);
			printf("dst port : %d\n",dst_port);
			printf("=========================\n");
		}	
	}

}


int main (int argc, char **argv)
{
	char *device = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcd;

	// pcap_t 를 열고 초기화하기 ( 1518은 이더넷 최고크기입니다. )
	pcd = pcap_open_live(device, 2048, NONPROMISC, -1, errbuf);
	if (!pcd) {
		fputs(errbuf, stderr);
		return 1;
	}

	if (pcap_set_datalink(pcd, DLT_EN10MB)) return 1;
	pcap_loop(pcd, -1, callback, NULL);
	return 0;
}
