#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger

import re
import socket

import ipaddress
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import v6mig.dns as dns

DISCOVERY_FQDN = '4over6.info'

VENDOR_ID = '000000-test_router'
PRODUCT = 'dslite_autoconfig'
VERSION = '0_2_0'
CAPABILITY = 'dslite'

logger = getLogger(__name__)

def query_dns(domain, q_type, nameservers):
    resolver = dns.DNSResolver

    try:
        if q_type == 'AAAA':
            return resolver.aaaa_query(domain = domain, server = nameservers.pop())
        if q_type == 'TXT':
            return resolver.txt_query(domain = domain, server = nameservers.pop())
    except (dns.DNSException, socket.timeout) as e:
        if len(nameservers):
            logger.warning("DNS Error. Retry with another DNS server.")
            return query_dns(domain, q_type, nameservers)
        else:
            logger.error("No response.")
            return None

def discover_provisioning_server(nameservers):
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

def get_provisioning_data(provisioning_server, vendorid = VENDOR_ID, product = PRODUCT, version = VERSION, capability = CAPABILITY, token = None, insecure = False):
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
