# Standard libraries
from itertools import combinations

# Additional libraries
from IPy import IP as IPy_IP


def powerset(iterable: iter) -> list:
    """powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"""
    pset = []
    for n in range(len(iterable) + 1):
        for sset in combinations(iterable, n):
            pset.append(sset)
    return pset


def let_user_pick_options(options: iter, force_selection: bool) -> int or None:
    attempted = False
    while not attempted or force_selection:
        print("Please choose:")
        for idx, element in enumerate(options):
            print("{}) {}".format(idx + 1, element))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(options):
                return int(i) - 1
        except Exception:
            pass
        attempted = True
    return None


def let_user_input_number(force_input: bool) -> int or None:
    attempted = False
    while not attempted or force_input:
        i = input("Enter number (int): ")
        try:
            return int(i)
        except Exception:
            pass
        attempted = True
    return None


def let_user_input_domain(force_input: bool) -> str or None:
    attempted = False
    while not attempted or force_input:
        s = input("Enter a domain (str): ")
        try:
            if len(str(s)) > 0:
                return str(s)
        except Exception:
            pass
        attempted = True
    return None


def let_user_input_ip(force_input: bool) -> str or None:
    attempted = False
    while not attempted or force_input:
        s = input("Enter a IP (str): ")
        try:
            if IPy_IP(str(s)):
                return str(s)
        except Exception:
            pass
        attempted = True
    return None


def get_mac_by_ip(ip: str, dictionary: dict) -> str or None:
    for mac in dictionary:
        if ip in dictionary[mac]:
            return mac
    return None
