import logging, ipaddress
from util.decorators import restful_method
from modules.netbox import NetboxUtility

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
        'add_pni',
        ]

logger = logging.getLogger(__name__)

@restful_method
def synchronize_devices(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    return NetboxUtility(test).synchronize_devices()


@restful_method
def generate_devices(method, data, params):

    data = NetboxUtility().generate_devices()

    return True, data, 'Devices generated from Netbox datasource'


@restful_method
def synchronize_interfaces(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    return NetboxUtility(test).synchronize_interfaces()


@restful_method
def generate_interfaces(method, data, params):

    data = NetboxUtility().generate_interfaces()

    return True, data, 'Interfaces generated from Netbox datasource'


@restful_method
def synchronize_igp(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    return NetboxUtility(test).synchronize_igp()


@restful_method
def generate_igp(method, data, params):
    data = NetboxUtility().generate_igp()

    return True, data, 'IGP configuration generated from Netbox datasource'


@restful_method
def synchronize_ebgp(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    return NetboxUtility(test).synchronize_ebgp()


@restful_method
def generate_ebgp(method, data, params):

    data = NetboxUtility().generate_ebgp()

    return True, data, 'Internal eBGP configuration generated from Netbox datasource'


@restful_method
def update_ptrs(method, data, params):
    test=True
    if params.get('test') in ['false', 'False']:
        test=False

    return NetboxUtility(test).script_runner('update_ptrs.UpdatePTRs')


@restful_method
def update_iface_descriptions(method, data, params):
    test=True
    if params.get('test') in ['false', 'False']:
        test=False

    return NetboxUtility(test).script_runner('update_iface_descriptions.UpdateIfaceDescriptions')


@restful_method
def renumber(method, data, params):
    test=True
    if params.get('test') in ['false', 'False']:
        test=False

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

    return NetboxUtility(test).script_runner('renumber.GenerateNew', data)


@restful_method
def prune_ips(method, data, params):
    test=True
    if params.get('test') in ['false', 'False']:
        test=False

    return NetboxUtility(test).script_runner('renumber.PruneIPs')


@restful_method
def add_pni(method, data, params):
    test=True
    if params.get('test') in ['false', 'False']:
        test=False

    # Validate IP addresses
    if ipv4 := data.get('my_ipv4'):
        try:
            ipaddress.IPv4Network(ipv4)
        except ValueError:
            return False, None, 'Invald IPv4 prefix'

    if  ipv6 := data.get('my_ipv6'):
        try:
            ipaddress.IPv6Network(ipv6)
        except ValueError:
            return False, None, 'Invald IPv6 prefix'

    return NetboxUtility(test).script_runner('add_pni.AddPNI', data)
