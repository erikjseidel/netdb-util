from copy       import deepcopy
import requests, json

from util.netdb import (
        NetdbException, netdb_get, netdb_validate, 
        netdb_add, netdb_replace, netdb_delete
        )

from util.decorators import restful_method
from config.netbox   import NETBOX_BASE, NETBOX_HEADERS

# Public symbols
__all__ = [ 'sync_netdb', 'generate_devices' ]

_NETDB_DEV_COLUMN   = 'device'
_NETDB_IFACE_COLUMN = 'interface'

class NetboxException(Exception):
    """Exception raised for failed / unexpected netbox API calls / results

    Attributes:
        url     -- CF API url
        message -- explanation of the error
    """
    def __init__(self, url, data, message):
        self.url     = url
        self.data    = data
        self.message = message
        super().__init__(self.message)


def _generate_devices():
    netbox_roles = {}
    netbox_sites = {}
    ibgp = {}

    out = {}

    url = NETBOX_BASE + '/api/dcim/devices/'
    netbox_dev = requests.get(url, headers = NETBOX_HEADERS).json().get('results')

    if not netbox_dev:
        raise NetboxException(url, None, 'netbox returned empty device set')

    for device in netbox_dev:
        device_id = device['id']
        name = device['name']

        out[name] = {}
        out[name]['cvars'] = {}

        custom = device.get('custom_fields')
        if custom:
            iso = custom.get('iso_address')
            if iso:
                out[name]['cvars']['iso'] = iso
            router_id = custom.get('router_id')
            if router_id:
                out[name]['cvars']['router_id'] = router_id

        slug = device['device_role']['slug']
        role = netbox_roles.get(slug)
        if not role:
            url  = device['device_role']['url']
            role = requests.get(url, headers = NETBOX_HEADERS).json() 
            netbox_roles[slug] = role

        try:
            roles = role['custom_fields']['netdb_roles']
        except KeyError:
            raise NetboxException(None, role, 'no netdb_roles found')

        slug = device['site']['slug']
        site = netbox_sites.get(slug)
        if not site:
            url  = device['site']['url']
            site = requests.get(url, headers = NETBOX_HEADERS).json() 
            netbox_sites[slug] = site

        try:
            # In the case of sites w/ multiple ASNs, assign first one.
            out[name]['cvars']['local_asn'] = site['asns'][0]['asn']
        except:
            raise NetboxException(None, site, 'Netbox found no ASNs for this site')

        try:
            custom = site['custom_fields']
            out[name].update({
                'location'  : custom['netdb_location_name'],
                'providers' : custom['site_providers'],
                'roles'     : roles + custom.get('netdb_roles'),
                })
        except KeyError:
            raise NetboxException(None, site, 'Netbox is missing one or more custome fields for this site')

        for i in ['ibgp_ipv4', 'ibgp_ipv6']:
            url = NETBOX_BASE + '/api/ipam/ip-addresses/?tag=%s&device_id=%s' % (i, str(device_id))
            ibgp = requests.get(url, headers = NETBOX_HEADERS).json().get('results')
            if ibgp:
                out[name]['cvars'][i] = ibgp[0]['address'].split('/')[0]

    return out


def _synchronize_netdb_entries(test = True):
    netbox_dev = _generate_devices()

    result, out, message = netdb_validate(_NETDB_DEV_COLUMN, data = netbox_dev)
    if not result:
        return result, out, message

    result, netdb_dev, message = netdb_get(_NETDB_DEV_COLUMN)
    if not result:
        netdb_dev = {}

    changes = {}

    for device, data in netbox_dev.items():
        if device in netdb_dev.keys():
            if data != netdb_dev[device]:
                # Update required.
                changes[device] = 'update required'
                if not test:
                    netdb_replace(_NETDB_DEV_COLUMN, data = { device : data })
            netdb_dev.pop(device)
        else:
            # Addition required
            if not test:
                netdb_add(_NETDB_DEV_COLUMN, data = { device : data })
            changes[device] = 'addition required'

    # Any remaining (unpopped) devices in netdb need to be deleted
    for device in netdb_dev.keys():
        # Deletion required
        if not test:
            netdb_delete(_NETDB_DEV_COLUMN, { 'id' : device })
        changes[device] = 'deletion required'

    if not changes:
        message = 'Netdb devices already in sync. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    return True if changes else False, changes, message


@restful_method(methods = ['GET', 'POST'])
def sync_netdb(method, data):
    test = True
    if method == 'POST':
        test = False

    return _synchronize_netdb_entries(test)


@restful_method
def generate_devices(method, data):
    try:
        data = _generate_devices()
    except NetboxException as e:
        return False, e.data, e.message

    return True, _generate_devices(), 'Devices generated from Netbox datasource'
