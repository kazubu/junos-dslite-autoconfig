#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger, Formatter, StreamHandler, DEBUG

import argparse
import copy
from jnpr.junos import Device

import junos_utils as junos
import v6mig


DNS_SERVERS = {
        "NTT_EAST": ['2404:1a8:7f01:a::3', '2404:1a8:7f01:b::3'],
        "NTT_WEST": ['2001:a7ff:5f01::a', '2001:a7ff:5f01:1::a']
        }

VENDOR_ID = '000000-test_router'
PRODUCT = 'dslite_autoconfig'
VERSION = '0_2_1'
CAPABILITY = 'dslite'

LOG_FORMAT = "[%(asctime)s] [%(levelname)s][%(name)s:%(lineno)s][%(funcName)s]: %(message)s"

IPIP_IFL = 'ip-0/0/0.0'

logger = getLogger(__name__)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--external-interface', required=True)
    parser.add_argument('--dns-from-dhcpv6')
    parser.add_argument('--area')
    parser.add_argument('--insecure')
    parser.add_argument('--debug')
    parser.add_argument('--ipip-ifl')

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

    interface_address = junos.get_interface_address(device, external_interface)
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
        dns_servers = junos.get_dhcpv6_dns_servers(device, external_interface)

    if(dns_servers is None):
        logger.error("DNS Server is not set. exit.")
        exit(2)

    logger.debug("DNS Servers: %s" % ', '.join(dns_servers))

    ps = v6mig.discover_provisioning_server(copy.copy(dns_servers))
    logger.debug("Provisioning server: %s" % ps)

    if(ps):
        insecure = True if args.insecure else False

        pd = v6mig.get_provisioning_data(provisioning_server = ps, nameservers = copy.copy(dns_servers), vendorid = VENDOR_ID, product = PRODUCT, version = VERSION, capability = CAPABILITY, insecure = insecure)
        logger.debug("Provisioning Data: %s" % pd)
    else:
        logger.error("Failed to retrieve provisioning server. exit.")
        exit(2)

    if(pd):
        aftr = v6mig.get_aftr_address(pd, copy.copy(dns_servers), multiple = True)
    else:
        logger.error("Failed to retrieve provisioning data. exit.")
        exit(2)

    if(len(aftr)):
        logger.debug("AFTR(s): %s", str(aftr))
        ipip_ifl = args.ipip_ifl if args.ipip_ifl else IPIP_IFL

        if len(aftr) > 1:
            current_aftr = junos.get_current_ipip_destination(device = device, ifl = ipip_ifl)
            logger.debug("Current configured AFTR: %s", current_aftr)
            selected_aftr = current_aftr if current_aftr in aftr else aftr[0]
        else:
            selected_aftr = aftr[0]

        logger.debug("Selected AFTR: %s" % selected_aftr)
        config = junos.generate_dslite_configuration(ifl = ipip_ifl, aftr = selected_aftr, source_address = interface_address)

        logger.debug("Generated configuration:\n%s", config)
    else:
        logger.error("Failed to retrieve AFTR IP address. exit.")
        exit(2)

    junos.update_configuration(device, config)

    device.close()

    exit()

