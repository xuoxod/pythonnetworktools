#! /usr/bin/python3

import re
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms


cus = cms["custom"]


""" IPv4 address """


def valid_ipv4(address=None):
    if not address == None:
        IPv4 = re.compile(r"([0-9]{1,3}\.){3}([0-9]{1,3})$")
        matched = re.search(IPv4, address)
        if not matched == None:
            return True
    return False


""" MAC address """


def valid_mac(address=None):
    if not address == None:
        IPv4 = re.compile(r"([0-9a-fA-F]{2}\:){5}([0-9a-fA-F]{2})$")
        matched = re.search(IPv4, str(address))
        return not matched == None
    return False


""" Network range  """


def valid_network_range(address=None):
    if not address == None:
        IPv4_network = re.compile(r"([0-9]{1,3}\.){3}([0-9]{1,3})\/[1-9]{1,3}$")
        matched = re.search(IPv4_network, str(address))
        return not matched == None
    return False


""" File extensions """


def has_ext(string=None):
    if not string == None:
        pattern = re.compile(r"(.)+(\.[a-z]{2,3})$")
        matched = re.search(pattern, string)

        try:
            assert not matched == None
            return True, matched
        except AssertionError as ae:
            msg = cus(255, 255, 255, "{}".format(ae))
            print("{}\n".format(msg))
            return False, None


def has_char(string=None, character=None):
    if not string == None and not character == None:
        return "{}".format(character) in string
    return False


def is_port_range(arg=None):
    if not arg == None:
        pattern = re.compile(r"^(([0-9]+)(\-))([0-9]+)|((\,)([0-9]+))+")
        matched = re.search(pattern, arg)
        arg_split = arg.split("-")
        sport = arg_split[0]
        eport = arg_split[1]

        try:
            valid_range = int(sport) < int(eport)
            assert not matched == None
            assert valid_range == True
            return True
        except AssertionError as ae:
            msg = cus(255, 255, 255, "{}".format(ae))
            print("{}\n".format(msg))
            return False
        except ValueError as ve:
            msg = cus(255, 255, 255, "{}".format(ve))
            print("{}\n".format(msg))
            return False


def is_port_number(arg):
    pattern = re.compile(r"^[0-9]+$")
    matched = re.search(pattern, arg)
    try:
        assert not matched == None
        return True
    except AssertionError as ae:
        return False
