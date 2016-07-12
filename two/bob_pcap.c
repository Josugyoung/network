#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <libnet.h>
#include <arpa/inet.h>

#define PROMISC 1
#define NONPROMISC 0

void callback (u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet ) {

	const struct libnet_ethernet_hdr * ether_packet = (const struct libnet_ethernet_hdr *)packet;
	uint8_t * d_mac = (uint8_t *)(ether_packet->ether_dhost);
	uint8_t * s_mac = (uint8_t *)(ether_packet->ether_shost);
	printf("=========================\n");
	printf("dst_mac : %02X:%02X:%02X:%02X:%02X:%02X\n", d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	printf("src_mac : %02X:%02X:%02X:%02X:%02X:%02X\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	
	if ( ntohs(ether_packet->ether_type) == ETHERTYPE_IP )
	{
		const struct libnet_ipv4_hdr * ip_packet = (const struct libnet_ipv4_hdr *)(packet+14);
		int ip_h_len = ip_packet->ip_hl*4;
		const uint32_t * ip_src_z = &(ip_packet->ip_src.s_addr);
		const uint8_t * ip_src = (const uint8_t *)ip_src_z;
		const uint32_t * ip_dst_z = &(ip_packet->ip_dst.s_addr);
		const uint8_t * ip_dst = (const uint8_t *)ip_dst_z;
		
		printf("src ip : %d.%d.%d.%d\n" , ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
		printf("dst ip : %d.%d.%d.%d\n" , ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3] );
		
		if ( ip_packet->ip_p == IPPROTO_TCP )
		{
			if ( ip_h_len < 20 )
				printf("비정상적인 IP 패킷입니다."); // 해커가 IP 패킷을 최소길이보다 작게 하는 경우 잘못된 주소 값을 참조하게 될 수 있어서 예외처리 해줍니다.
			const struct libnet_tcp_hdr *tcp_packet = (const struct libnet_tcp_hdr *)(packet+14+ip_h_len); 
			printf("src port : %u\n",(u_short)ntohs(tcp_packet->th_sport));
			printf("dst port : %u\n",(u_short)ntohs(tcp_packet->th_dport));
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
