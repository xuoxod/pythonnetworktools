from scapy.all import *
from .PlatformConstants import LINE_SEP as lsep, SEP as sep
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from .PatternConstants import valid_ipv4 as vip4, valid_mac as vma

cus = cms["custom"]

""" Private Addresses """


def who_has_a(target="10.0.0.0/8"):
    destination = "ff:ff:ff:ff:ff:ff"
    verbose = 0
    timeout = 2
    results = None
    clients = []

    packet = Ether(dst=destination) / ARP(pdst=target)

    results = srp(packet, timeout=timeout, vebose=verbose)[0]

    if not results == None:
        for sent, recv in results:
            clients.append({"ip": str(recv.psrc), "mac": str(recv.hwsrc)})

    if len(clients) > 0:
        return {
            "status": True,
            "clients": clients,
            "msg": "Found {} devices on the network".format(len(clients)),
        }

    return {"status": False, "reason": "Could not detect any devices on the network"}


def who_has_b(target="172.16.0.0/16"):
    destination = "ff:ff:ff:ff:ff:ff"
    verbose = 0
    timeout = 2
    results = None
    clients = []

    packet = Ether(dst=destination) / ARP(pdst=target)

    results = srp(packet, timeout=timeout, vebose=verbose)[0]

    if not results == None:
        for sent, recv in results:
            clients.append({"ip": str(recv.psrc), "mac": str(recv.hwsrc)})

    if len(clients) > 0:
        return {
            "status": True,
            "clients": clients,
            "msg": "Found {} devices on the network".format(len(clients)),
        }

    return {"status": False, "reason": "Could not detect any devices on the network"}


def who_has_c(target="192.168.0.0/24"):
    destination = "ff:ff:ff:ff:ff:ff"
    verbose = 0
    timeout = 2
    results = None
    clients = []

    packet = Ether(dst=destination) / ARP(pdst=target)

    results = srp(packet, timeout=timeout, verbose=verbose)[0]

    if not results == None:
        for sent, recv in results:
            clients.append({"ip": str(recv.psrc), "mac": str(recv.hwsrc)})

    if len(clients) > 0:
        return {
            "status": True,
            "clients": clients,
            "msg": "Found {} devices on the network".format(len(clients)),
        }

    return {"status": False, "reason": "Could not detect any devices on the network"}


def who_has(target, mask):
    results = None
    if mask == "a":
        results = who_has_a(target)
    if mask == "b":
        results = who_has_b(target)
    if mask == "c":
        results = who_has_c(target)
    if not results == None:
        status = results["status"]
        if status:
            clients = results["clients"]
            print(*clients, sep="\n")
        else:
            reason = results["reason"]
            print("{}\n".format(reason))
