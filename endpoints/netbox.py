import logging, ipaddress
from util.decorators import restful_method
from modules import netbox
from modules.netbox import NetboxException

# Public symbols
__all__ = [
        'synchronize_devices',
        'synchronize_interfaces',
        'synchronize_igp',
        'synchronize_ebgp',
        'generate_devices',
        'generate_interfaces',
        'generate_igp',
        'generate_ebgp',
        'update_ptrs',
        'update_iface_descriptions',
        'renumber',
        'prune_ips',
        ]

logger = logging.getLogger(__name__)

@restful_method
def synchronize_devices(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return netbox.synchronize_devices(test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_devices(method, data, params):
    try:
        data = netbox.generate_devices()

    except NetboxException as e:
        logger.error(f'exception at netbox.generate_devices: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'Devices generated from Netbox datasource'


@restful_method
def synchronize_interfaces(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return netbox.synchronize_interfaces(test=test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_interfaces(method, data, params):
    try:
        data = netbox.generate_interfaces()
    except NetboxException as e:
        return False, { 'api_url': e.url, 'code': e.code }, e.message

    return True, data, 'Interfaces generated from Netbox datasource'


@restful_method
def synchronize_igp(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return netbox.synchronize_igp(test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_igp(method, data, params):
    try:
        data = netbox.generate_igp()

    except NetboxException as e:
        logger.error(f'exception at netbox.generate_igp: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'IGP configuration generated from Netbox datasource'


@restful_method
def synchronize_ebgp(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return netbox.synchronize_ebgp(test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_ebgp(method, data, params):
    try:
        data = netbox.generate_ebgp()

    except NetboxException as e:
        logger.error(f'exception at netbox.generate_ebgp: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'Internal eBGP configuration generated from Netbox datasource'


@restful_method
def update_ptrs(method, data, params):
    commit = False
    if params.get('test') in ['false', 'False']:
        commit = True

    return netbox.script_runner('update_ptrs.UpdatePTRs', commit=commit)


@restful_method
def update_iface_descriptions(method, data, params):
    commit = False
    if params.get('test') in ['false', 'False']:
        commit = True

    return netbox.script_runner('update_iface_descriptions.UpdateIfaceDescriptions', commit=commit)


@restful_method
def renumber(method, data, params):
    commit = False
    if params.get('test') in ['false', 'False']:
        commit = True

    # Validate input parameters
    if not ( ipv4 := params.get('ipv4') ):
        return False, None, 'IPv4 prefix (ipv4) required'
    try:
        ipaddress.IPv4Network(ipv4)
    except ValueError:
        return False, None, 'Invald IPv4 prefix'

    if not ( ipv6 := params.get('ipv6') ):
        return False, None, 'IPv6 prefix (ipv6) required'
    try:
        ipaddress.IPv6Network(ipv6)
    except ValueError:
        return False, None, 'Invald IPv6 prefix'

    data = { 'ipv4_prefix': ipv4, 'ipv6_prefix': ipv6 }

    return netbox.script_runner('renumber.GenerateNew', data, commit=commit)


@restful_method
def prune_ips(method, data, params):
    commit = False
    if params.get('test') in ['false', 'False']:
        commit = True

    return netbox.script_runner('renumber.PruneIPs', commit=commit)
