#! /usr/bin/python3

import argparse
from custom_modules.Utils import exit_prog
from custom_modules.PlatformConstants import LINE_SEP as lsep
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.IPPatterns import (
    valid_ipv4 as vip4,
    valid_network_range as vna,
    is_port_number as port,
    is_port_range as prange,
)
from custom_modules.MyLogger import create_log as log

cus = cms["custom"]
desc = "Perform network tasks"
epil = "Light weight network tasks"
app_log_dir_name = "ntools"
app_error_log_name = "ntools-errors.log"
app_log_name = "ntools-logs.log"
file_type = (
    "python files",
    "*.py",
)


def error_handler(*args):
    e_msg_head = cus(255, 121, 121, "Error ")
    e_msg_body = ""
    for i, a in enumerate(args):
        if i < (len(args) - 1):
            e_msg_body += cus(255, 255, 255, "{}{}".format(a, lsep))
        else:
            e_msg_body += cus(255, 255, 255, "{}".format(a))
    e_msg = "{}\t{}".format(e_msg_head, e_msg_body)
    print("{}{}".format(e_msg, lsep))
    exit_prog()


def print_version():
    print("ntools 0.1")
    log("ntools: printed version", app_log_dir_name, app_log_name)
    exit_prog()


parser = argparse.ArgumentParser(description=desc, epilog=epil)
parser.error = error_handler

# Display app version
version = parser.add_mutually_exclusive_group()
version.add_argument(
    "-v",
    "--version",
    dest="version",
    action="store_true",
    help="print version and exit",
)

# Arp who has
who_has = parser.add_argument_group("ARP who has", "detect hosts on the network")
who_has.add_argument(
    "-t",
    "--type",
    dest="type",
    type=int,
    choices=range(1, 4),
    help="network type: 1=Class A, 2=Class B, 3=Class C",
)
who_has.add_argument("-l", "--lan", dest="lan", type=str, help="expects an IP or CIDR")

# Route info
route_info = parser.add_argument_group("Route info", "IP, gateway info")
route_info.add_argument(
    "-r", "--route", dest="route", action="store_true", help="show route info and exit"
)
route_info.add_argument(
    "-i", "--ip", dest="ip", action="store_true", help="show IP address and exit"
)
route_info.add_argument(
    "-n",
    "--name",
    dest="name",
    action="store_true",
    help="show network interface name and exit",
)

# Scan port(s)
scan_host = parser.add_argument_group("Port scanning", "scan single host or network")
scan_host.add_argument(
    "-s", "--scan", dest="scan", nargs=1, help="expects an IP or CIDR"
)
scan_host.add_argument(
    "-p",
    "--hport",
    dest="hport",
    nargs=1,
    help="expects an integer or range: e.g. 22, 1-2048.",
)


args = parser.parse_args()

if args.version:
    print_version()

elif args.lan:
    address = args.lan
    mask = "c"

    if not vip4(address) and not vna(address):
        e_header = cus(255, 122, 122, "Error:")
        e_body = cus(
            255,
            255,
            255,
            "Expecting a valid IP address or CIDR but received {}".format(address),
        )
        e_msg = "{}\t{}".format(e_header, e_body)
        print("{}\n".format(e_msg))
        exit_prog()

    if args.type:
        type = args.type
        if type == 1:
            mask = "a"
        elif type == 2:
            mask = "b"
        else:
            mask = "c"
    else:
        mask = "c"

    print("who has:\taddress: {} type: {}".format(address, mask))

elif args.scan:
    address = args.scan[0]
    hport = "1-1025"

    if args.hport:
        _port = args.hport[0]

        # TODO: validate proper port range

        if not port(_port) and not prange(_port):
            e_header = cus(255, 122, 122, "Error:")
            e_body = cus(
                255,
                255,
                255,
                "Expecting a valid port number or range. e.g. 22, 1-2048.",
            )
            e_msg = "{}\t{}".format(e_header, e_body)
            print("{}\n".format(e_msg))
            exit_prog()
        else:
            hport = args.hport[0]

    print("Scanning {} port(s) {}".format(address, hport))
