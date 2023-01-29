#! /usr/bin/python3

import argparse
from custom_modules.Utils import exit_prog
from custom_modules.PlatformConstants import LINE_SEP as lsep
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.MyLogger import create_log as log

cus = cms["custom"]
desc = "Perform network tasks"
epil = "Scans hosts and display route info"
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


parser = argparse.ArgumentParser(description=desc, epilog=epil)
parser.error = error_handler

# Display app version
version = parser.add_mutually_exclusive_group()
version.add_argument(
    "-v",
    "--version",
    dest="version",
    action="store_true",
    help="Print version to stdout",
)

args = parser.parse_args()

if args.version:
    print_version()
