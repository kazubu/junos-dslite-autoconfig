#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger

import re
import socket

import ipaddress
import json
import requests
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from . import dns

DISCOVERY_FQDN = '4over6.info'

VENDOR_ID = '000000-test_router'
PRODUCT = 'dslite_autoconfig'
VERSION = '0_2_0'
CAPABILITY = 'dslite'

logger = getLogger(__name__)

original_create_connection = urllib3.util.connection.create_connection
global_nameservers = []

def query_dns(domain, q_type, nameservers, multiple = False):
    resolver = dns.DNSResolver

    try:
        if q_type == 'AAAA':
            return resolver.aaaa_query(domain = domain, server = nameservers.pop(), multiple = multiple)
        if q_type == 'TXT':
            return resolver.txt_query(domain = domain, server = nameservers.pop())
    except (dns.DNSException, socket.timeout) as e:
        if len(nameservers):
            logger.warning("DNS Error. Retry with another DNS server.")
            return query_dns(domain, q_type, nameservers, multiple = multiple)
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

def get_aftr_address(provisioning_data, nameservers, multiple = False):
    aftr = provisioning_data['dslite']['aftr']
    if('.' in aftr):
        logger.debug("It seems it's FQDN. Try to query AAAA to DNS server.")
        aftr = query_dns(domain = aftr, q_type = 'AAAA', nameservers = nameservers, multiple = multiple)

    return aftr

def custom_create_connection(address, *args, **kwargs):
    host, port = address
    hostname = query_dns(host, 'AAAA', global_nameservers)

    return original_create_connection((hostname, port), *args, **kwargs)

def get_provisioning_data(provisioning_server, nameservers, vendorid = VENDOR_ID, product = PRODUCT, version = VERSION, capability = CAPABILITY, token = None, insecure = False):
    global global_nameservers
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

    global_nameservers = nameservers
    urllib3.util.connection.create_connection = custom_create_connection

    try:
        response = requests.get(url, params = params, verify = verify_tls_cert).text
    except requests.exceptions.SSLError as ex:
        logger.error("SSL Error is detected.")
        return None

    return json.loads(response)
