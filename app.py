#! /usr/bin/python3

from custom_modules.RouteInfo import print_routing_table
from custom_modules.Arper import who_has_a as whoa,who_has_b as whob,who_has_c as whoc

print_routing_table()

results = whoc("192.168.12.0/24")
status = results['status']

if status:
    clients = results['clients']
    print(*clients,sep="\n" +"-"*100+"\n")
else:
    reason = results['reason']
    print("{}\n".format(reason))

