#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger, Formatter, StreamHandler, DEBUG

import os
import random
import re
import socket
import string
import struct
import sys

import argparse
import ipaddress
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DISCOVERY_FQDN = '4over6.info'
DNS_SERVERS = {
        "NTT_EAST": ['2404:1a8:7f01:a::3', '2404:1a8:7f01:b::3'],
        "NTT_WEST": ['2001:a7ff:5f01::a', '2001:a7ff:5f01:1::a']
        }

VENDOR_ID = '000000-test_router'
PRODUCT = 'dslite_autoconfig'
VERSION = '0_2_0'
CAPABILITY = 'dslite'

LOG_FORMAT = "[%(asctime)s] [%(levelname)s][%(name)s:%(lineno)s][%(funcName)s]: %(message)s"
CONFIGURATION_FORMAT = """
set interfaces ip-0/0/0 unit 0 family inet
set interfaces ip-0/0/0 unit 0 tunnel source ${source_address}
set interfaces ip-0/0/0 unit 0 tunnel destination ${aftr}
"""[1:-1]

logger = getLogger(__name__)

'''
DNS Implementation
'''

TYPE_TXT         = 16
TYPE_AAAA        = 28
OPCODE_QUERY   = 0
CLASS_IN      = 1


class DNSException(Exception):
    """All our exceptions."""


class DNSUtils():
    @staticmethod
    def read_name(data: bytes, start_offset: int):
        """Read DNS name (with compression!) from the whole message starting at specified offset."""
        ret_len = 0
        ret_str = ""
        while True:
            l = data[start_offset + ret_len]
            if l >= 0xC0:     #offset
                offset = struct.unpack("!H", data[start_offset + ret_len : start_offset + ret_len + 2])[0]
                offset = offset & 0x3FFF

                label, _ = DNSUtils.read_name(data, offset)

                ret_str += label
                ret_len += 2
                break       #because pointer is ALWAYS the last element
            #else...
            ret_len += 1
            if l == 0:
                break
            ret_str += data[start_offset + ret_len: start_offset + ret_len + l].decode() + "."
            ret_len += l
            if len(data) == start_offset + ret_len:
                break

        if not ret_str:
            return ("<ROOT>", ret_len)
        if ret_str[-1] == ".":
            ret_str = ret_str[:-1]
        return (ret_str, ret_len)

    @staticmethod
    def read_aaaa(data: bytes, start_offset: int):
        ip = ipaddress.IPv6Address(data[start_offset:start_offset+16])
        return (ip.compressed, len(ip.compressed))

class MessageHeader():      # pylint: disable=too-many-instance-attributes
    """DNS message header."""
    def __init__(self):
        self.ID = random.randrange(0, 0xFFFF)                   # pylint: disable=invalid-name
        self.QR = 0                                             # pylint: disable=invalid-name
        self.OPCODE = 0                                         # pylint: disable=invalid-name
        self.AA = 0                                             # pylint: disable=invalid-name
        self.TC = 0                                             # pylint: disable=invalid-name
        self.RD = 0                                             # pylint: disable=invalid-name
        self.RA = 0                                             # pylint: disable=invalid-name
        self.Z = 0                                              # pylint: disable=invalid-name
        self.RCODE = 0                                          # pylint: disable=invalid-name

        #they will be set by DNSMessage
        self.QDCOUNT = 0                                        # pylint: disable=invalid-name
        self.ANCOUNT = 0                                        # pylint: disable=invalid-name
        self.NSCOUNT = 0                                        # pylint: disable=invalid-name
        self.ARCOUNT = 0                                        # pylint: disable=invalid-name

    def __bytes__(self):
        """Convert to bytes."""
        ret = struct.pack("!H", self.ID)        #ID

        i = (self.QR & 0x01) << 15
        i = i + ((self.OPCODE& 0x0F) << 14)
        i = i + ((self.AA & 0x01) << 10)
        i = i + ((self.TC & 0x01) << 9)
        i = i + ((self.RD & 0x01) << 8)

        i = i + ((self.RA & 0x01) << 7)
        i = i + ((self.Z & 0x07) << 6)
        i = i + (self.RCODE & 0x0F)
        ret += struct.pack("!H", i)        #QR, Opcode, AA, TC, RD, RA, Z, RCODE

        ret += struct.pack("!HHHH", self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)
        return ret

    def __len__(self):
        """Return length of message header - 6 words always."""
        return 6 * 2

    def read(self, data: bytes):
        """Deserialize object from data."""
        if len(data) < len(self):
            return 0
        self.ID, i = struct.unpack("!HH", data[:4])

        self.QR = (i >> 15) & 0x01
        self.OPCODE = (i >> 11) & 0x0F
        self.AA = (i >> 10) & 0x01
        self.TC = (i >> 9) & 0x01
        self.RD = (i >> 8) & 0x01
        self.RA = (i >> 7) & 0x01
        self.Z = (i >> 4) & 0x07
        self.RCODE = i & 0x0F

        self.QDCOUNT, self.ANCOUNT = struct.unpack("!HH", data[4 : 8])
        self.NSCOUNT, self.ARCOUNT = struct.unpack("!HH", data[8 : 12])
        return len(self)

class ResourceRecord():
    """Resource record."""
    def __init__(self):
        self.name = ""
        self.rdata_type = 0
        self.rdata_class = 0
        self.ttl = 0
        self.rdata_len = 0
        self.rdata = "NOT IMPLEMENTED"

    def __bytes__(self):
        raise NotImplementedError

    def read(self, data: bytes, offset: int):
        """Deserialize object from data."""
        self.name, length = DNSUtils.read_name(data, offset)
        offset += length

        self.rdata_type, self.rdata_class = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4

        self.ttl, self.rdata_len = struct.unpack("!LH", data[offset : offset + 6])
        offset += 6

        if self.rdata_class == CLASS_IN:
            if self.rdata_type == TYPE_TXT:
                self.rdata, _ = DNSUtils.read_name(data, offset)
            elif self.rdata_type == TYPE_AAAA:
                self.rdata, _ = DNSUtils.read_aaaa(data, offset)
        else:
            self.rdata = "UNSUPPORTED CLASS"

        return length + 10 + self.rdata_len

class DNSQuestion():
    """DNS question."""
    def __init__(self):
        self.name = ""
        self.type = 0
        self.q_class = 0

    def __bytes__(self):
        """Convert to bytes."""
        ret = b""
        parts = self.name.split('.')
        for part in parts:
            part_len = len(part)
            if part_len > 63:
                raise DNSException("Name is too long")
            ret += struct.pack("B", part_len)
            ret += part.encode()

        ret += struct.pack("!BHH", 0x00, self.type, self.q_class)
        return ret

    def read(self, data: bytes, offset: int):
        """Deserialize object from bytes."""
        self.name, length = DNSUtils.read_name(data, offset)
        offset += length
        self.type, self.q_class = struct.unpack("!HH", data[offset : offset + 4])
        return length + 4

class DNSMessage():
    """DNS message."""
    def __init__(self, data = None):
        self.header = MessageHeader()
        self.questions: list[DNSQuestion] = []
        self.answers: list[ResourceRecord] = []
        self.authorities: list[ResourceRecord] = []
        self.additionals: list[ResourceRecord] = []

        if data:
            self.read(data)

    def __bytes__(self):
        """Convert to bytes."""
        self.header.QDCOUNT = len(self.questions)
        self.header.ANCOUNT = len(self.answers)
        self.header.NSCOUNT = len(self.authorities)
        self.header.ARCOUNT = len(self.additionals)

        ret = bytes(self.header)

        for question in self.questions:
            ret += bytes(question)
        for answer in self.answers:
            ret += bytes(answer)
        for authority in self.authorities:
            ret += bytes(authority)
        for additional in self.additionals:
            ret += bytes(additional)
        return ret

    def read(self, data: bytes):
        """Deserialize object from data."""
        pos = self.header.read(data)

        self.questions.clear()
        for _ in range(self.header.QDCOUNT):
            question = DNSQuestion()
            pos += question.read(data, pos)
            self.questions.append(question)

        self.answers.clear()
        for _ in range(self.header.ANCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.answers.append(record)

        self.authorities.clear()
        for _ in range(self.header.NSCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.authorities.append(record)

        self.additionals.clear()
        for _ in range(self.header.ARCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.additionals.append(record)

class DNSResolver():
    def udp_query(domain: str,          # pylint: disable=too-many-arguments
                  q_type: int,
                  server: str = "8.8.8.8",
                  port: int = 53,
                  timeout: float = 2,
                  recursive: bool = True
                  ):
        """Perform simple UDP query."""

        ret:list[ResourceRecord] = []
        #Creating a message
        message = DNSMessage()
        message.header.OPCODE = OPCODE_QUERY
        if recursive:
            message.header.RD = 1
        question = DNSQuestion()
        question.name = domain
        question.type = q_type
        question.q_class = CLASS_IN
        message.questions.append(question)

        #sending request
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        data = bytes(message)
        if len(data) > 512:
            raise DNSException("UDP message is too long for DNS!")
        sock.sendto(data, (server, port))

        #reading response
        try:
            reply = sock.recv(512)
        except TimeoutError:
            reply = b""

        for answer in DNSMessage(reply).answers:
            if answer.rdata_type != q_type:     #YES, WE CAN receive extra responses
                continue
            ret.append(answer)
        return ret

    def simple_query(domain: str,
                  q_type: int,
                  server: str,
                  port: int = 53,
                  ):
        result = None
        answers = DNSResolver.udp_query(domain, q_type = q_type, server = server, port = port)
        for a in answers:
            if a.rdata_type == q_type:
                result = a.rdata
                break;

        return result

    def aaaa_query(domain: str,
                  server: str,
                  port: int = 53
                  ):
        result = DNSResolver.simple_query(domain, q_type = TYPE_AAAA, server = server, port = port)
        return result

    def txt_query(domain: str,
                  server: str,
                  port: int = 53
                  ):
        result = DNSResolver.simple_query(domain, q_type = TYPE_TXT, server = server, port = port)
        return result

'''
Main Implementation
'''

def query_dns(domain, q_type, nameservers):
    resolver = DNSResolver

    try:
        if q_type == 'AAAA':
            return resolver.aaaa_query(domain = domain, server = nameservers.pop())
        if q_type == 'TXT':
            return resolver.txt_query(domain = domain, server = nameservers.pop())
    except (DNSException, socket.timeout) as e:
        if len(nameservers):
            logger.warning("DNS Error. Retry with another DNS server.")
            return query_dns(domain, q_type, nameservers)
        else:
            logger.error("No response.")
            return None

def discover_provisioning_server(nameservers):
    resolver = DNSResolver

    response_txt = query_dns(domain = DISCOVERY_FQDN, q_type = 'TXT', nameservers = nameservers)
    logger.debug("Response TXT: %s" % response_txt)

    if response_txt == None:
        return None

    response_list = re.split('[\s=]', response_txt)
    result = {response_list[i]: response_list[i + 1] for i in range(0, len(response_list), 2)}

    return result

def get_aftr_address(provisioning_data, nameservers):
    aftr = provisioning_data['dslite']['aftr']
    logger.debug("AFTR Address: %s" % aftr)
    if('.' in aftr):
        logger.debug("It seems it's FQDN. Try to query AAAA to DNS server.")
        aftr = query_dns(domain = aftr, q_type = 'AAAA', nameservers = nameservers)

    return aftr

def get_provisioning_data(provisioning_server, vendorid, product, version, capability, token = None, insecure = False):
    url = provisioning_server['url']
    t = provisioning_server['t']

    params = {}
    params["vendorid"] = vendorid
    params["product"] = product
    params["version"] = version
    params["capability"] = capability
    params["token"] = token

    verify_tls_cert = True if t == 'b' else False
    verify_tls_cert = False if insecure else verify_tls_cert
    logger.debug("TLS Certificate verification: %s" % str(verify_tls_cert))

    response = json.loads(requests.get(url, params=params, verify=verify_tls_cert).text)

    return response

def generate_dslite_configuration(aftr, source_address):
    return string.Template(CONFIGURATION_FORMAT).substitute(aftr = aftr, source_address = source_address)

def get_interface_address(device, interface_name):
    interfaces = device.rpc.get_interface_information(interface_name = interface_name, terse = True)

    for ifa in interfaces.getiterator("address-family"):
        if ifa.find("address-family-name").text.strip() == "inet6":
            for ifa in ifa.getiterator("interface-address"):
                addr = ifa.find("ifa-local").text.strip()
                if addr[0:4] != 'fe80' and ':' in addr:
                    return addr.split('/')[0]
    return None

def get_dhcpv6_dns_servers(device, interface_name):
    dhcpv6_detail = device.rpc.get_dhcpv6_client_binding_information_by_interface(interface_name = interface_name, detail = True)

    for dhcp_option in dhcpv6_detail.getiterator("dhcp-option"):
        option_name = dhcp_option.find("dhcp-option-name")
        if option_name is not None and option_name.text.strip() == "dns-recursive-server":
            return dhcp_option.find("dhcp-option-value").text.strip().split(',')

    return None

def update_configuration(device, configuration):
    try:
        with Config(device) as cu:
            cu.lock()

            cu.load(configuration, format="set", merge = True)

            if(cu.diff()):
                logger.info("Configuration should be updated. Committing...")
                cu.commit(comment = 'DS-Lite configuration update')
            else:
                logger.info("Configuration is not changed.")

            cu.unlock()
    except JunosException.LockError as e:
        logger.error("Failed to lock configuration database. Candidate configuration is may found.")
        logger.error(e)
    except JunosException.RpcError as e:
        logger.error("Failed to commit configuration.")
        logger.error(e)


if __name__ == '__main__':
    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config
    from jnpr.junos import exception as JunosException

    parser = argparse.ArgumentParser()
    parser.add_argument('--external-interface', required=True)
    parser.add_argument('--dns-from-dhcpv6')
    parser.add_argument('--area')
    parser.add_argument('--insecure')
    parser.add_argument('--debug')
    args = parser.parse_args()

    if(args.dns_from_dhcpv6 is None and args.area is None):
        logger.error("Option --dns-from-dhcpv6 or --area [AREA] is required.")
        exit(1)


    handler = StreamHandler()
    handler.setFormatter(Formatter(LOG_FORMAT))
    logger.addHandler(handler)
    if(args.debug):
        logger.setLevel(DEBUG)

    device = Device()
    device.open()

    external_interface = args.external_interface
    logger.debug("External interface: %s" % external_interface)

    interface_address = get_interface_address(device, external_interface)
    if(interface_address == None):
        logger.error("Interface has no IPv6 address!")
        exit(2)

    logger.debug("Interface address: %s" % interface_address)

    dns_servers = None
    if(args.area):
        if(args.area in DNS_SERVERS):
            dns_servers = DNS_SERVERS[args.area]
        else:
            logger.error("Area %s is not found! exit." % args.area)
            exit(1)
    else:
        dns_servers = get_dhcpv6_dns_servers(device, external_interface)

    if(dns_servers is None):
        logger.error("DNS Server is not set. exit.")
        exit(2)

    logger.debug("DNS Servers: %s" % ', '.join(dns_servers))

    ps = discover_provisioning_server(dns_servers)
    logger.debug("Provisioning server: %s" % ps)

    if(ps):
        insecure = True if args.insecure else False

        pd = get_provisioning_data(provisioning_server = ps, vendorid = VENDOR_ID, product = PRODUCT, version = VERSION, capability = CAPABILITY, insecure = insecure)
        logger.debug("Provisioning Data: %s" % pd)
    else:
        logger.error("Failed to retrieve provisioning server. exit.")
        exit(2)

    if(pd):
        aftr = get_aftr_address(pd, dns_servers)
    else:
        logger.error("Failed to retrieve provisioning data. exit.")
        exit(2)

    if(aftr):
        config = generate_dslite_configuration(aftr = aftr, source_address = interface_address)
    else:
        logger.error("Failed to retrieve AFTR IP address. exit.")
        exit(2)

    update_configuration(device, config)

    device.close()

    exit()

