from scapy.all import *


def get_routing_table():
    route_info = conf.route.route()
    interface = route_info[0]
    address = route_info[1]
    gateway = route_info[2]
    return {"interface": interface, "address": address, "gateway": gateway}


def print_routing_table():
    route_info = conf.route.route()
    interface = route_info[0]
    address = route_info[1]
    gateway = route_info[2]
    print(
        "Interface: {}\nAddress: {}\nGateway: {}\n".format(interface, address, gateway)
    )


def get_network_interface_name():
    return conf.iface


def print_network_interface_name():
    iface = conf.iface
    print("{}".format(iface))


def get_network_interface_hardware_address():
    return get_if_hwaddr(conf.iface)


def print_network_interface_hardware_address():
    print("{}".format(get_if_hwaddr(conf.iface)))
