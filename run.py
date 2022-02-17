#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger, Formatter, StreamHandler

import os
import re
import sys

import dns.resolver

DISCOVERY_FQDN = '4over6.info'
FALLBACK_DNS_SERVERS = ['2404:1a8:7f01:a::3', '2404:1a8:7f01:b::3']

LOG_FORMAT = "[%(asctime)s] [%(levelname)s][%(name)s:%(lineno)s][%(funcName)s]: %(message)s"

logger = getLogger(__name__)

def discover_provisioning_server(nameservers = None):
    resolver = dns.resolver.Resolver()
    if nameservers != None:
        resolver.nameservers = nameservers

    try:
        response_txt = str(resolver.resolve(DISCOVERY_FQDN, 'TXT')[0])[1:-1]

    except dns.resolver.NoAnswer as e:
        if nameservers == None:
            logger.warning("No response with system DNS server. Retry with NGN DNS server.")
            return discover_provisioning_server(FALLBACK_DNS_SERVERS)
        else:
            logger.error("No response.")
            return None

    response_list = re.split('[\s=]', response_txt)
    result = {response_list[i]: response_list[i + 1] for i in range(0, len(response_list), 2)}

    return result

if __name__ == '__main__':
    handler = StreamHandler()
    handler.setFormatter(Formatter(LOG_FORMAT))
    logger.addHandler(handler)

    print(discover_provisioning_server())
    exit()

