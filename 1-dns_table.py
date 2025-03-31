#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import rich
from rich import box
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from pprint import pprint
import socket


_iface = 'ens33'

# https://en.wikipedia.org/wiki/List_of_DNS_record_types
dns_qtype = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    28: 'AAAA',
}

table = Table(
    "Request type",
    "Source IP",
    "Resolver",
    "Request Domain name",
    "Record type",
    "Answer"
    # box=box.SIMPLE
)


def dns_type_1(src_ip, resolver_ip, pkt, ix):
    r_type = "> RESPONSE"
    r_name = pkt.an.rrname
    r_record_type = 'A'
    ip = pkt.an[DNSRR][ix].rdata
    try:
        socket.inet_aton(ip)
    except:
        pass
    else:
        add_row(r_type, src_ip, resolver_ip, r_name, r_record_type, str(ip))


def dns_type_28(src_ip, resolver_ip, pkt, ix):
    r_type = "> RESPONSE"
    r_name = pkt.an.rrname
    r_record_type = 'AAAA'
    ip = pkt.an[DNSRR][ix].rdata
    try:
        socket.inet_pton(ip)
    except:
        pass
    else:
        add_row(r_type, src_ip, resolver_ip, r_name, r_record_type, str(ip))


def dns_type_5(src_ip, resolver_ip, pkt, ix):
    r_type = "> RESPONSE"
    r_name = pkt.an.rrname
    r_record_type = 'CNAME'
    cname = pkt.an[DNSRR][ix].rdata
    add_row(r_type, src_ip, resolver_ip, r_name, r_record_type, str(cname.decode('utf-8')))


def add_row(r_type, src_ip, resolver_ip, r_name, r_record_type, r_result):
    table.add_row(
            r_type,
            src_ip,
            resolver_ip,
            r_name.decode('utf-8'),
            str(r_record_type),
            r_result
        )

def dns(pkt):
    if pkt.haslayer(DNS):
        src_ip = pkt['IP'].src
        resolver_ip = pkt['IP'].dst

        # qr = 0: query
        if pkt.qr == 0 and pkt.qdcount > 0 and isinstance(pkt.qd, DNSQR):
            #qdcount: so luong cau hoi
            r_type = "> QUERY"
            r_name = pkt.qd.qname
            r_record_type_int = pkt.qd.qtype

            try:
                r_record_type = dns_qtype[r_record_type_int]
            except:
                e_record_type = r_record_type_int

            r_result = ''
            add_row(r_type, src_ip, resolver_ip, r_name, r_record_type, r_result)

        # qr = 1: answer
        elif pkt.qr ==1 and pkt.ancount > 0 and isinstance(pkt.an, DNSRR):
            #ancount: so luong cau tra loi
            for ix in range(pkt.ancount):
                if pkt.an[DNSRR][ix].type == 1:  # A record (IPv4)
                    dns_type_1(src_ip, resolver_ip, pkt, ix)
                if pkt.an[DNSRR][ix].type == 28: # AAAA record (IPv6)
                    dns_type_28(src_ip, resolver_ip, pkt, ix)
                if pkt.an[DNSRR][ix].type == 5:  # CNAME record (IPv4)
                    dns_type_5(src_ip, resolver_ip, pkt, ix)

with Live(table, refresh_per_second=5):
    sniff(iface=_iface, filter="udp and port 53", count=0, store=0, prn=dns)
