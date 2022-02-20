from logging import getLogger
import string

from jnpr.junos.utils.config import Config
from jnpr.junos import exception as JunosException


CONFIGURATION_FORMAT = """
set interfaces ip-0/0/0 unit 0 family inet
set interfaces ip-0/0/0 unit 0 tunnel source ${source_address}
set interfaces ip-0/0/0 unit 0 tunnel destination ${aftr}
"""[1:-1]

logger = getLogger(__name__)

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

