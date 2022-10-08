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

company_name  = w.registrar

server = w.whois_server

country = w.country

state = w.state

org = w.org

if company_name == None:
	company_name = "None"

if server == None:
	server = "None"

if country == None:
	country = "None"

if state == None:
	state = "None"

if org == None:
	org = "None"


#erver = w.whois_server
#country = w.country
#state = w.state
#org = w.orgs


##creation_date = w.creation_date[0]
##expiration_date = w.expiration_date[0]

nmapData = []


f = open(f'whois_{target}.txt','w')
f.write(company_name+'\n'+server+'\n'+country+'\n'+state+'\n'+org+'\n')
f.close()


def nmapScan():
	res=scanner.scan(hosts=ip_address,arguments="--script dns-brute");
	# print(res)
	# print(res['nmap']['scaninfo']['tcp']["services"])
	oports=res['scan'][ip_address]['tcp'];
	l=len(res['scan'][ip_address]['tcp']);
	for port in oports:
		nmapData.append(str(port) + " " + str(oports[port]['name']) + " " + str(oports[port]['state']))
		nmapData.append(str(datetime.datetime.now()))

nmapScan()


# while(True):
#     nmapScan()
#     time.sleep(20)

