#!/usr/bin/env python3

from scapy.all import *
from pprint import pprint

_iface = 'ens33'

def dns(pkt):
    if 'DNS' in pkt:
        pprint(pkt)
        ip = pkt['IP'].src
        domain = pkt['DNS Question Record'].qname[:-1]

        print(f"IP: {ip}, Domain: {domain.decode('utf-8')}")


sniff(iface=_iface, filter="port 53", count=0, store=0, prn=dns)