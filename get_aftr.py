#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import copy

import v6mig

LOG_FORMAT = "[%(asctime)s] [%(levelname)s][%(name)s:%(lineno)s][%(funcName)s]: %(message)s"
DNS_SERVERS = {
        "NTT_EAST": ['2404:1a8:7f01:a::3', '2404:1a8:7f01:b::3'],
        "NTT_WEST": ['2001:a7ff:5f01::a', '2001:a7ff:5f01:1::a']
        }

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--area', required=True)
    parser.add_argument('--insecure')
    args = parser.parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    area = args.area

    insecure = True if args.insecure else False

    if(not (area in DNS_SERVERS)):
        print("Area %s is not found! exit." % area)
        exit(1)

    ps = v6mig.discover_provisioning_server(copy.copy(DNS_SERVERS[area]))
    print("Provisioning server: %s" % ps)

    if(ps):
        pd = v6mig.get_provisioning_data(provisioning_server = ps, nameservers = copy.copy(DNS_SERVERS[area]), insecure = insecure)
        print("Provisioning Data: %s" % pd)
    else:
        print("Failed to retrieve provisioning server. exit.")
        exit(2)

    if(pd):
        aftr = v6mig.get_aftr_address(pd, copy.copy(DNS_SERVERS[area]))
    else:
        print("Failed to retrieve provisioning data. exit.")
        exit(2)

    print("AFTR Address: %s" % aftr)

    exit()

