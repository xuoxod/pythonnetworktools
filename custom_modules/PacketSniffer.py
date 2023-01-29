import logging
from scapy.all import *
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms


logging.basicConfig(filemode="scapy-info-log", level=logging.INFO)
logging.basicConfig(filemode="scapy-warning-log", level=logging.WARNING)
logging.basicConfig(filemode="scapy-error-log", level=logging.ERROR)
logging.basicConfig(filemode="scapy-critical-log", level=logging.CRITICAL)

cus = cms["custom"]

""" Send TCP packet 
    @param obj_packet: A Scapy packet
"""


def send_tcp_packet(destination, start_port, end_port, timeout=0):
    results = None

    results = sr(
        IP(dst=destination) / TCP(sport=start_port, dport=end_port),
        timeout=timeout,
    )

    if not results == None:
        print(results)
        return {"status": True, "data": results}
    else:
        return {"status": False, "reason": "No results"}

    # sr1(IP(dst="192.168.1.1")/TCP(sport=5000,dport=6000,flags="A"),timeout=4)
