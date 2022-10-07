import nmap
import socket
import pyfiglet
import sys
import datetime
import time
import whois


scanner = nmap.PortScanner()

# print(pyfiglet.figlet_format("TuringScanner"))

target=sys.argv[1]
ip_address = socket.gethostbyname(target)

print("*"*50);

print(f"\tTarget Domain: {target}")
print(f"\tIP Address: {ip_address}")



w = whois.whois(target)

print(f"""
	registerar:{w['registrar']}
	{w['registrar_url']}
	{w['creation_date']}
	{w['expiration_date']}
	{w['name_servers']}
	{w['organization']}
	
	""")


def nmapScan():
	res=scanner.scan(hosts=ip_address,arguments="--script dns-brute");
	# print(res)
	# print(res['nmap']['scaninfo']['tcp']["services"])
	oports=res['scan'][ip_address]['tcp'];
	l=len(res['scan'][ip_address]['tcp']);
	for port in oports:
		print("\t",port, oports[port]['name'], oports[port]['state'])
	print("\t",datetime.datetime.now())

nmapScan()
# while(True):
#     nmapScan()
#     time.sleep(20)

