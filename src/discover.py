# Standard libraries
from threading import Lock
from time import sleep

# Additional libraries
from IPy import IP as IPy_IP
from scapy import packet
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff


def passive(interface: str, settings: dict):
    try:
        hosts_dictionary: dict = settings['hosts'][interface]
        lock: Lock = settings['locks'][interface]
        attacker_mac = get_if_hwaddr(interface)
        attacker_ip = get_if_addr(interface)

        def host_found(mac: str, ip: str):
            if mac == attacker_mac:
                return
            if ip == attacker_ip:
                return

            if mac == '00:00:00:00:00:00':
                return
            if IPy_IP(ip).iptype() != 'PRIVATE':
                return
            last_ip_part = ip.split('.')[3]
            if last_ip_part == '255' or last_ip_part == '0':
                return
            if mac not in hosts_dictionary:
                if settings['show discovery']:
                    print('New host discovered at IP ' + ip + ' with MAC ' + mac + ' on interface ' + interface)
                lock.acquire()
                new_dict = dict({mac: {ip}})
                hosts_dictionary.update(new_dict)
                lock.release()
            elif ip not in hosts_dictionary[mac]:
                if settings['show discovery']:
                    print(
                        'Alternative location for host discovered at IP ' + ip + ' with MAC ' + mac + ' on interface ' + interface)
                lock.acquire()
                hosts_dictionary[mac].add(ip)
                lock.release()

        def ip_callback(received_packet: packet):
            if IP in received_packet:
                src_mac = received_packet[Ether].src
                src_ip = received_packet[IP].src
                host_found(src_mac, src_ip)
                dst_mac = received_packet[Ether].dst
                dst_ip = received_packet[IP].dst
                host_found(dst_mac, dst_ip)
            if ARP in received_packet:
                if received_packet[ARP].op == 0:
                    src_mac = received_packet[ARP].hwsrc
                    src_ip = received_packet[ARP].psrc
                    host_found(src_mac, src_ip)
                elif received_packet[ARP].op == 1:
                    src_mac = received_packet[ARP].hwsrc
                    src_ip = received_packet[ARP].psrc
                    host_found(src_mac, src_ip)
                    dst_mac = received_packet[ARP].hwdst
                    dst_ip = received_packet[ARP].pdst
                    host_found(dst_mac, dst_ip)

        print('Passively discovering new hosts on ' + interface)
        while not settings['interrupted']:
            if settings['currently discovering']:
                sniff(iface=interface, prn=ip_callback, store=0, timeout=1)
            else:
                sleep(1)
    except Scapy_Exception:
        print('Scapy cannot operate on interface ' + interface)
        main_lock = settings['main lock']
        main_lock.acquire()
        settings['chosen interfaces'].remove(interface)
        main_lock.release()
