#! /usr/bin/python3

from custom_modules.RouteInfo import print_routing_table
from custom_modules.Arper import who_has_c as whohas
from custom_modules.PacketSniffer import send_tcp_packet as send_tpa

print_routing_table()

results = whohas("192.168.12.0/24")

status = results["status"]

if status:
    clients = results["clients"]

    print(*clients, sep="\n")
else:
    reason = results["reason"]
    print("{}\n".format(reason))

send_tpa()