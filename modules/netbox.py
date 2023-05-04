
import requests, json
from copy import deepcopy
from util.decorators import restful_method
from util.netdb import (
        NetdbException, netdb_get, netdb_validate, 
        netdb_add, netdb_replace, netdb_delete
        )
from config.netbox import ( 
        NETBOX_BASE, NETBOX_HEADERS, NETBOX_SOURCE,
        NETBOX_ETHERNET, NETBOX_NETDB
        )

from pprint import pprint

# Public symbols
__all__ = [ 'sync_netdb', 'generate_devices', 'generate_interfaces' ]

_NETDB_DEV_COLUMN   = 'device'
_NETDB_IFACE_COLUMN = 'interface'

_FILTER = { 'datasource': NETBOX_SOURCE['name'] }


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


def _generate_ibgp_ips():
    bgp_ips = {}
    for i in ['ibgp_ipv4', 'ibgp_ipv6']:
        url = NETBOX_BASE + '/api/ipam/ip-addresses/?tag=%s' % i
        nb_bgp_ips = requests.get(url, headers = NETBOX_HEADERS).json().get('results')
        for ip in nb_bgp_ips:
            device = ip['assigned_object']['device']['name']
            if device not in bgp_ips:
                bgp_ips[device] = {}
            bgp_ips[device][i] = ip['address']

    return bgp_ips


def _generate_providers():
    tag = 'wan_port'
    providers = {}

    url = NETBOX_BASE + '/api/dcim/interfaces/?tag=%s' % tag
    ifaces = requests.get(url, headers = NETBOX_HEADERS).json().get('results')

    for iface in ifaces:
        device = iface['device']['name']
        if device not in providers:
            providers[device] = []

        # Upstreams in cloud providers (such as Vultr) are marked as VXLAN EXPN type
        # L2VPNs in Netbox.
        vxlan = iface.get('l2vpn_termination')
        if vxlan and vxlan['l2vpn'] not in providers[device]:
            providers[device].append(vxlan['l2vpn'])

        # Physical upstreams (such as MyRepublic) use traditional circuits in Netbox.
        for link_peer in iface.get('link_peers'):
            if link_peer['circuit']:
                url = link_peer['circuit']['url']
                provider = requests.get(url, headers = NETBOX_HEADERS).json().get('provider')
                if provider and provider not in providers[device]:
                    providers[device].append(provider)

    return providers


def _generate_fw_contexts():
    out = {}

    url = NETBOX_BASE + '/api/extras/config-contexts/'
    contexts = requests.get(url, headers = NETBOX_HEADERS).json().get('results')

    for context in contexts:
        for tag in context['tags']:
            if tag.startswith('fw_') and context['is_active']:
                if tag in out and out[tag]['weight'] > context['weight']:
                    continue

                out[tag] = {
                    'weight' :  context['weight'],
                    'data'   :  context['data'],
                    }
    return out


def _generate_device_ips(device_id):
    url = NETBOX_BASE + '/api/ipam/ip-addresses/?device_id=%s' % device_id
    ips = requests.get(url, headers = NETBOX_HEADERS).json().get('results')
    out = {}

    for ip in ips:
        if ip['status']['value'] != 'active':
            continue

        assert ip['assigned_object']['device']['id'] == device_id

        parent = ip['assigned_object']['name']

        if parent not in out:
            out[parent] = []

        tags = [ i['name'] for i in ip['tags'] ]

        entry = {
            'address'  :  ip['address'],
            'family'   :  ip['family']['label'],
            }

        if ip['dns_name']:
            entry['ptr'] = ip['dns_name']
        if ip['tags']:
            entry['tags'] = tags

        out[parent].append(entry)

    return out


def _generate_virtual_links():
    url = NETBOX_BASE + '/api/dcim/virtual-links/'
    links = requests.get(url, headers = NETBOX_HEADERS).json().get('results')
    out = {}

    for link in links:
        for end in ['interface_a', 'interface_b']:
            other = 'interface_b' if end == 'interface_a' else 'interface_a'

            device = link[end]['device']['name']
            if device not in out:
                out[device] = {}

            out[device].update({
                link[end]['name']: {
                    'status'  : link['status']['value'],
                    'tags'    : [ i['name'] for i in link['tags'] ],
                    'peer'    : {
                        'device'    : link[other]['device']['name'],
                        'interface' : link[other]['name'],
                        },
                    },
                })

            if link['custom_fields']['tunnel_key']:
                out[device][ link[end]['name'] ]['key'] = link['custom_fields']['tunnel_key']

    return out


def _generate_interfaces(device, tag=None):
    out = {}

    url = NETBOX_BASE + '/api/dcim/devices/?name=%s' % device
    try:
        device_id = requests.get(url, headers = NETBOX_HEADERS).json()['results'][0]['id']
    except:
        raise NetboxException(url, None, 'device %s not found in netbox' % device)

    url = NETBOX_BASE + '/api/ipam/ip-addresses/?device_id=%s' % device_id
    device_ips = {
            device : _generate_device_ips(device_id),
            }

    url = NETBOX_BASE + '/api/dcim/interfaces/?device_id=%s' % str(device_id)
    if tag: url += '?tag=%s' % str(tag)

    ifaces_in = requests.get(url, headers = NETBOX_HEADERS).json().get('results')
    if not ifaces_in: 
        raise NetboxException(url, None, 'no matching interfaces found on %s' % device)

    fw_contexts = _generate_fw_contexts()
    virtual_links = _generate_virtual_links()

    for iface in ifaces_in:
        name = iface['name']

        out[name] = {}

        type = iface['type']['value']
        if type in NETBOX_ETHERNET:
            out[name].update({
                'type'      :  'ethernet',
                'vyos_type' :  'ethernet',
                })
        elif type in NETBOX_NETDB:
            # directly mapped types
            out[name].update({
                'type'      :  type,
                })
        else:
            raise NetboxException(url, None, '%s: invalid type for %s' % (device, name) )

        # if virtual link is not marked as connected then disable.
        try:
           if virtual_links[device][name]['status'] != 'connected':
                out[name]['disabled'] = True
        except KeyError:
            pass

        if not iface['enabled']:
            out[name]['disabled'] = True

        for k in ['description', 'mtu']:
            v = iface.get(k)
            if v:
                out[name][k] = v

        if iface['custom_fields']['ttl']:
            out[name]['ttl'] = iface['custom_fields']['ttl']

        if iface['type']['value'] in ['gre', 'l2gre']:
            # Get source IP and interface for tunnels
            if iface['parent']:
                parent =  iface['parent']['name']
                ips = device_ips[device].get(parent)
                if ips:
                    for ip in ips:
                        if 'tun_src' in ip['tags']:
                            out[name]['source'] = ip['address'].split('/')[0]
                            break

                if iface['custom_fields']['bind_parent']:
                    out[name]['interface'] = parent

            # Get remote IP address
            try:
                # there should only ever be one link_peer
                assert len(iface['link_peers']) == 1

                peer_name  = iface['link_peers'][0]['device']['name']
                peer_iface = iface['link_peers'][0]['name']
                if peer_name not in device_ips:
                    peer_device = iface['link_peers'][0]['device']['id']
                    device_ips[peer_name] = _generate_device_ips(peer_device)

                url = iface['link_peers'][0]['url']
                peer_iface_parent = requests.get(url, headers = NETBOX_HEADERS).json()['parent']['name']

                for ip in device_ips[peer_name][peer_iface_parent]:
                    if 'tun_src' in ip['tags']:
                        out[name]['remote'] = ip['address'].split('/')[0]

            except KeyError:
                # This tunnel is not wired or its remote has no eligible remote so nothing to be done.
                pass

        ips = device_ips[device].get(name) or []
        for ip in ips:
            addr = ip['address']
            if 'addresses' not in out[name]:
                out[name]['addresses'] = {}
            
            if 'ptr' in ip or 'tags' in ip:
                meta = {}
                if 'ptr' in ip:
                    meta['dns'] = { 'ptr' : ip['ptr'] }
                if 'tags' in ip:
                    meta['tags'] = ip['tags']

                out[name]['addresses'][addr] = { 'meta': meta }
            else:
                out[name]['addresses'][addr] = None

        tags = [ i['name'] for i in iface['tags'] ]

        # TBD: Order by v['weight']
        fw_sets = [ v for k, v in fw_contexts.items() if k in tags ]

        for fw in fw_sets:
            out[name]['firewall'] = fw['data']

    return out


def _generate_devices():
    netbox_roles = {}
    netbox_sites = {}
    out = {}

    url = NETBOX_BASE + '/api/dcim/devices/'
    netbox_dev = requests.get(url, headers=NETBOX_HEADERS).json().get('results')
    if not netbox_dev:
        raise NetboxException(url, None, 'netbox returned empty device set')

    bgp_ips = _generate_ibgp_ips()
    providers = _generate_providers()

    for device in netbox_dev:
        if device['status']['value'] not in ['active', 'staged']:
            continue

        slug = device['site']['slug']
        site = netbox_sites.get(slug)
        if not site:
            url  = device['site']['url']
            site = requests.get(url, headers = NETBOX_HEADERS).json() 
            netbox_sites[slug] = site

        if site['status']['value'] not in ['active', 'staging', 'decommissioning']:
            continue

        slug = device['device_role']['slug']
        role = netbox_roles.get(slug)
        if not role:
            url  = device['device_role']['url']
            role = requests.get(url, headers = NETBOX_HEADERS).json() 
            netbox_roles[slug] = role

        device_id = device['id']
        name = device['name']

        out[name] = {}
        out[name]['datasource'] = NETBOX_SOURCE['name']
        out[name]['weight']     = NETBOX_SOURCE['weight']
        out[name]['meta'] = {
                'netbox' : {
                    'id'            :  device_id,
                    'last_updated'  :  device['last_updated'],
                    'status'        :  device['status']['value'],
                    },
                }

        out[name]['cvars'] = {}

        custom = device.get('custom_fields')
        if custom:
            iso = custom.get('iso_address')
            if iso:
                out[name]['cvars']['iso'] = iso
            router_id = custom.get('router_id')
            if router_id:
                out[name]['cvars']['router_id'] = router_id

        try:
            roles = role['custom_fields']['netdb_roles']
        except KeyError:
            raise NetboxException(None, role, 'no netdb_roles found')

        try:
            # In the case of sites w/ multiple ASNs, assign first one.
            out[name]['cvars']['local_asn'] = site['asns'][0]['asn']
        except:
            raise NetboxException(None, site, 'Netbox found no ASNs for this site')

        out[name]['cvars']['local_asn'] = site['asns'][0]['asn']

        try:
            custom = site['custom_fields']
            out[name].update({
                'location'  : site['region']['display'],
                'roles'     : roles + custom.get('netdb_roles'),
                })

        except KeyError:
            raise NetboxException(None, site, 'Netbox is missing one or more custom fields for this site')

        for i in ['ibgp_ipv4', 'ibgp_ipv6']:
            ips = bgp_ips.get(name)
            if ips and i in ips:
                out[name]['cvars'][i] = ips[i].split('/')[0]

        if name in providers:
            for provider in providers[name]:
                if 'providers' not in out[name]:
                    out[name]['providers'] = []
                out[name]['providers'].append(provider['slug'])

    return out


def _synchronize_netdb_entries(test = True):
    netbox_dev = _generate_devices()

    result, out, message = netdb_validate(_NETDB_DEV_COLUMN, data = netbox_dev)
    if not result:
        return result, out, message

    result, netdb_dev, message = netdb_get(_NETDB_DEV_COLUMN, data = _FILTER)
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

    try:
        return _synchronize_netdb_entries(test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_devices(method, data):
    try:
        data = _generate_devices()
    except NetboxException as e:
        return False, e.data, e.message

    return True, data, 'Devices generated from Netbox datasource'


@restful_method
def generate_interfaces(method, data):

    name = 'SIN2'

    try:
        data = _generate_interfaces(name)
    except NetboxException as e:
        return False, { 'api_url': e.url }, e.message

    return True, data, 'Interfaces generated from Netbox datasource for %s' % name
