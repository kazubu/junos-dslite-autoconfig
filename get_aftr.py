#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import dslite_autoconfig

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--area', required=True)
    parser.add_argument('--insecure')
    args = parser.parse_args()

    handler = dslite_autoconfig.StreamHandler()
    handler.setFormatter(dslite_autoconfig.Formatter(dslite_autoconfig.LOG_FORMAT))
    dslite_autoconfig.logger.addHandler(handler)
    dslite_autoconfig.logger.setLevel(dslite_autoconfig.DEBUG)

    area = args.area

    insecure = True if args.insecure else False

    if(not (area in dslite_autoconfig.DNS_SERVERS)):
        print("Area %s is not found! exit." % area)
        exit(1)

    ps = dslite_autoconfig.discover_provisioning_server(dslite_autoconfig.DNS_SERVERS[area])
    print("Provisioning server: %s" % ps)

    if(ps):
        pd = dslite_autoconfig.get_provisioning_data(provisioning_server = ps, vendorid = dslite_autoconfig.VENDOR_ID, product = dslite_autoconfig.PRODUCT, version = dslite_autoconfig.VERSION, capability = dslite_autoconfig.CAPABILITY, insecure = insecure)
        print("Provisioning Data: %s" % pd)
    else:
        print("Failed to retrieve provisioning server. exit.")
        exit(2)

    if(pd):
        aftr = dslite_autoconfig.get_aftr_address(pd, dslite_autoconfig.DNS_SERVERS[area])
    else:
        print("Failed to retrieve provisioning data. exit.")
        exit(2)

    print("AFTR Address: %s" % aftr)

    exit()

