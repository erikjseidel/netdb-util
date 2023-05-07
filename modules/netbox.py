import requests, json, logging
from copy import deepcopy
from util.decorators import restful_method
from config import netbox
from util.netdb import (
        NetdbException, netdb_get, netdb_validate, 
        netdb_add, netdb_replace, netdb_delete
        )

# Public symbols
__all__ = [
        'synchronize_devices',
        'synchronize_interfaces',
        'generate_devices',
        'generate_interfaces',
        ]

_NETDB_DEV_COLUMN   = 'device'
_NETDB_IFACE_COLUMN = 'interface'

_FILTER = { 'datasource': netbox.NETBOX_SOURCE['name'] }

logger = logging.getLogger(__name__)

class Netbox:
    _BASE = netbox.NETBOX_BASE
    _HEADERS = netbox.NETBOX_HEADERS
    
    def __init__(self, endpoint=None):
        self.set(endpoint)

    def set(self, endpoint):
        self.url = self._BASE + '/api'

        if endpoint:
            if not endpoint.startswith('/'):
                self.url += '/'
            if not endpoint.endswith('/'):
                endpoint += '/'
            self.url += endpoint
        return self

    def set_url(self, url):
        self.url = url
        return self

    def get(self, **kwargs):
        url = self.url + '?'

        tags = kwargs.pop('tags', None)

        for k, v in kwargs.items():
            if v:
                url += '%s=%s&' % (k, v)

        if tags:
            if isinstance(tags, list):
                for tag in tags:
                    url += 'tag=%s&' % tag
            else:
                url += 'tag=%s' % tags

        # clean up url
        if url.endswith('?') or url.endswith('&'):
            url = url[:-1]

        logger.debug(f'Netbox.get: {url}')
        resp = requests.get(url, headers = self._HEADERS)
        
        if (code := resp.status_code) != 200:
            raise NetboxException(url, resp.json(), code)

        if 'results' in ( json := resp.json() ):
            return json['results']
        return json


class NetboxException(Exception):
    """Exception raised for failed / unexpected netbox API calls / results

    Attributes:
        url     -- CF API url
        message -- explanation of the error
    """
    def __init__(self, url=None, data=None, code=None, message=None):
        self.url     = url
        self.data    = data
        self.code    = code
        self.message = message
        super().__init__(self.message)


def _generate_ibgp_ips():
    bgp_ips = {}
    for i in ['ibgp_ipv4', 'ibgp_ipv6']:
        for ip in Netbox('/ipam/ip-addresses').get(tags=i):
            device = ip['assigned_object']['device']['name']
            if device not in bgp_ips:
                bgp_ips[device] = {}
            bgp_ips[device][i] = ip['address']

    return bgp_ips


def _generate_providers():
    tag = 'wan_port'
    providers = {}

    nb = Netbox('/dcim/interfaces')
    for iface in nb.get(tags=tag):
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
            if circuit := link_peer['circuit']:
                provider = nb.set_url(circuit['url']).get().get('provider')

                if provider and provider not in providers[device]:
                    providers[device].append(provider)

    return providers


def _generate_fw_contexts():
    out = {}

    for context in Netbox('/extras/config-contexts').get():
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
    out = {}

    for ip in Netbox('/ipam/ip-addresses').get(device_id=device_id):
        if ip['status']['value'] != 'active':
            continue

        assert ip['assigned_object']['device']['id'] == device_id

        if (parent := ip['assigned_object']['name']) not in out:
            out[parent] = []

        entry = {
            'address'  :  ip['address'],
            'family'   :  ip['family']['label'],
            }

        if ptr := ip['dns_name']:
            entry['ptr'] = ptr

        if ip['tags']:
            tags = [ i['name'] for i in ip['tags'] ]
            entry['tags'] = tags

        out[parent].append(entry)

    return out


def _generate_virtual_links():
    out = {}

    for link in Netbox('/dcim/virtual-links').get():
        for end in ['interface_a', 'interface_b']:
            other = 'interface_b' if end == 'interface_a' else 'interface_a'

            device = link[end]['device']['name']
            if device not in out:
                out[device] = {}

            name = link[end]['name']
            out[device].update({
                name: {
                    'status'  : link['status']['value'],
                    'tags'    : [ i['name'] for i in link['tags'] ],
                    'peer'    : {
                        'device'    : link[other]['device']['name'],
                        'interface' : link[other]['name'],
                        },
                    },
                })

            if key := link['custom_fields']['tunnel_key']:
                out[device][name]['key'] = key

    return out


def _generate_devices():
    netbox_roles = {}
    netbox_sites = {}
    out = {}

    nb = Netbox('/dcim/devices')
    if not ( netbox_dev := nb.get() ):
        raise NetboxException(url, None, 'netbox returned empty device set')

    bgp_ips   = _generate_ibgp_ips()
    providers = _generate_providers()

    for device in netbox_dev:
        # only load devices that are active or in staging
        if device['status']['value'] not in ['active', 'staged']:
            continue

        slug = device['site']['slug']
        if not ( site := netbox_sites.get(slug) ):
            site = nb.set_url(device['site']['url']).get()
            netbox_sites[slug] = site

        # only load devices in sites with certain statuses
        if site['status']['value'] not in ['active', 'staging', 'decommissioning']:
            continue

        slug = device['device_role']['slug']
        if not ( role := netbox_roles.get(slug) ):
            role = nb.set_url(device['device_role']['url']).get()
            netbox_roles[slug] = role

        device_id = device['id']
        name = device['name']

        entry = {}
        cvars = {}

        if custom := device.get('custom_fields'):
            iso = custom.get('iso_address')
            if iso:
                cvars['iso'] = iso
            router_id = custom.get('router_id')
            if router_id:
                cvars['router_id'] = router_id

        try:
            roles = role['custom_fields']['netdb_roles']
        except KeyError:
            raise NetboxException(None, role, 'no netdb_roles found')

        try:
            # In the case of sites w/ multiple ASNs, assign first one.
            cvars['local_asn'] = site['asns'][0]['asn']
        except:
            raise NetboxException(None, site, 'Netbox found no ASNs for this site')

        cvars['local_asn'] = site['asns'][0]['asn']

        try:
            custom = site['custom_fields']
            entry.update({
                'location'  : site['region']['display'],
                'roles'     : roles + custom.get('netdb_roles'),
                })

        except KeyError:
            raise NetboxException(None, site, 'Netbox is missing one or more custom fields for this site')

        for i in ['ibgp_ipv4', 'ibgp_ipv6']:
            ips = bgp_ips.get(name)
            if ips and i in ips:
                cvars[i] = ips[i].split('/')[0]

        if name in providers:
            for provider in providers[name]:
                if 'providers' not in entry:
                    entry['providers'] = []
                entry['providers'].append(provider['slug'])

        # Add netbox metadata
        entry['datasource'] = netbox.NETBOX_SOURCE['name']
        entry['weight']     = netbox.NETBOX_SOURCE['weight']
        entry['meta'] = {
                'netbox' : {
                    'id'            :  device_id,
                    'url'           :  device['url'],
                    'last_updated'  :  device['last_updated'],
                    'status'        :  device['status']['value'],
                    },
                }

        entry['cvars'] = cvars
        out[name] = entry

    return out


def _generate_interfaces(device, in_tag=None, in_name=None):
    out = {}

    nb = Netbox('/dcim/devices/')
    try:
        device_id = nb.get(name=device)[0]['id']
    except:
        raise NetboxException(code=404, message='device %s not found in netbox' % device)

    if not ( ifaces_in := nb.set('/dcim/interfaces/').get(device_id=device_id, name=in_name, tags=in_tag) ):
        raise NetboxException(code=404, message='no matching interfaces found on %s' % device)

    fw_contexts   = _generate_fw_contexts()
    virtual_links = _generate_virtual_links()
    device_ips    = { device : _generate_device_ips(device_id) }

    # Used to build lag interfaces
    device_ifaces = None

    for iface in ifaces_in:
        name = iface['name']

        iface_tags = [ i['name'] for i in iface['tags'] ]

        # Unmanaged interfaces are ignored
        if 'unmanaged' in iface_tags:
            continue

        entry = {}

        type = iface['type']['value']
        if type in netbox.NETBOX_ETHERNET:
            entry['type'] = 'ethernet'

        elif type in netbox.NETBOX_NETDB:
            entry['type'] = type

        elif type == 'lag':
            entry['type'] = 'lacp'

            lacp =  {
                    'rate'        : 'fast',
                    'min_links'   : 1,
                    'hash_policy' : 'layer2+3',
                    'members'     : [],
                    }

            if 'layer3+4' in iface_tags:
                lacp['hash_policy'] = 'layer3+4'

            if not device_ifaces:
                device_ifaces = Netbox('/dcim/interfaces/').get(device_id=device_id)

            for i in device_ifaces:
                if i['lag'] and i['lag'].get('id') == iface['id']:
                    lacp['members'].append(i['name'])

            entry['lacp'] = lacp

        elif type == 'vlan':
            entry['type'] = type

            if not iface['untagged_vlan']:
                raise NetboxException(
                        message = '%s %s: untagged VLAN ID is required' % (device, name)
                        )

            if not iface['parent']:
                raise NetboxException(
                        message = '%s %s: parent interface required' % (device, name) 
                        )

            parent = iface['parent']['name']

            vlan =  {
                    'id': iface['untagged_vlan']['vid'],
                    'parent' : parent,
                    }

            entry['vlan'] = vlan

        else:
            raise NetboxException( message = '%s: invalid type for %s' % (device, name) )

        # if virtual link is not marked as connected then disable.
        if iface['virtual_link'] and virtual_links[device][name]['status'] != 'connected':
                out[name]['disabled'] = True

        if not iface['enabled']:
            entry['disabled'] = True

        for k in ['description', 'mtu']:
            v = iface.get(k)
            if v:
                entry[k] = v

        if iface['custom_fields']['ttl']:
            entry['ttl'] = iface['custom_fields']['ttl']

        if iface['type']['value'] in ['gre', 'l2gre']:
            # Get source IP and interface for tunnels
            if iface['parent']:
                parent =  iface['parent']['name']
                ips = device_ips[device].get(parent)
                if ips:
                    for ip in ips:
                        if 'tun_src' in ip['tags']:
                            entry['source'] = ip['address'].split('/')[0]
                            break

                if iface['custom_fields']['bind_parent']:
                    entry['interface'] = parent

            if iface['link_peers'] and iface['virtual_link']:
                # there should only ever be one link_peer
                assert len(iface['link_peers']) == 1

                link_peer = iface['link_peers'][0]

                peer_name  = link_peer['device']['name']
                peer_iface = link_peer['name']

                # we haven't lazy loaded this device yet
                if peer_name not in device_ips:
                    device_ips[peer_name] = _generate_device_ips(link_peer['device']['id'])

                url = link_peer['url']
                peer_iface_parent = nb.set_url(link_peer['url']).get()['parent']['name']

                for ip in device_ips[peer_name][peer_iface_parent]:
                    if 'tun_src' in ip['tags']:
                        entry['remote'] = ip['address'].split('/')[0]

        for ip in (device_ips[device].get(name) or []):
            addr = ip['address']
            if 'address' not in entry:
                entry['address'] = {}
            
            if 'ptr' in ip or 'tags' in ip:
                meta = {}
                if 'ptr' in ip:
                    meta['dns'] = { 'ptr' : ip['ptr'] }
                if 'tags' in ip:
                    meta['tags'] = ip['tags']

                entry['address'][addr] = { 'meta': meta }
            else:
                entry['address'][addr] = None

        # TBD: Order by v['weight']
        fw_sets = [ v for k, v in fw_contexts.items() if k in iface_tags ]

        for fw in fw_sets:
            entry['firewall'] = fw['data']

        # Add netbox metadata
        entry['datasource'] = netbox.NETBOX_SOURCE['name']
        entry['weight']     = netbox.NETBOX_SOURCE['weight']
        entry['meta'] = {
                'netbox' : {
                    'id'            :  iface['id'],
                    'url'           :  iface['url'],
                    'last_updated'  :  iface['last_updated'],
                    },
                }

        out[name] = entry

    return out


def _synchronize_devices(test = True):
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
            filt = { "id": device, **_FILTER }
            netdb_delete(_NETDB_IFACE_COLUMN, data = filt)
        changes[device] = 'removal from netdb required'

    if not changes:
        message = 'Netdb devices already in sync. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    if not test:
        logger.info(f'_synchronize_devices: {message}')

    return True if changes else False, changes, message


def _synchronize_interfaces(device, interface = None, test = True):
    netbox_ifaces = { device : _generate_interfaces(device, in_name=interface) }

    result, out, message = netdb_validate(_NETDB_IFACE_COLUMN, data = netbox_ifaces)
    if not result:
        return result, out, message

    result, netdb_ifaces, message = netdb_get(_NETDB_IFACE_COLUMN, data = { 'set_id': device, **_FILTER })
    if not result:
        netdb_ifaces = { device : {} }

    changes = {}


    for iface, data in netbox_ifaces[device].items():
        if iface in netdb_ifaces[device].keys():
            if data != netdb_ifaces[device][iface]:
                # Update required.
                changes[iface] = 'update required'
                if not test:
                    netdb_replace(_NETDB_IFACE_COLUMN, data = { device: { iface : data }})
            netdb_ifaces[device].pop(iface)
        else:
            # Addition required
            if not test:
                netdb_add(_NETDB_IFACE_COLUMN, data = { device: { iface : data }})
            changes[iface] = 'addition required'

    # Any remaining (unpopped) devices in netdb need to be deleted
    for iface in netdb_ifaces[device].keys():
        # Deletion required
        if not test:
            filt = { "set_id": device, "element_id": iface, **_FILTER }
            netdb_delete(_NETDB_IFACE_COLUMN, data = filt)
        changes[iface] = 'removal from netdb required'

    if not changes:
        message = 'Netdb devices already in sync. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    if not test:
        logger.info(f'_synchronize_interfaces: {message}')

    return True if changes else False, changes, message


@restful_method(methods = ['GET', 'POST'])
def synchronize_devices(method, data):
    test = True
    if method == 'POST':
        test = False

    try:
        return _synchronize_devices(test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_devices(method, data):
    try:
        data = _generate_devices()

    except NetboxException as e:
        logger.error(f'exception at netbox.generate_devices: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'Devices generated from Netbox datasource'


@restful_method(methods = ['GET', 'POST'])
def synchronize_interfaces(method, data):
    test = True
    if method == 'POST':
        test = False

    if not data.get('device'):
        return False, None, 'No device selected'

    device= data.get('device').upper()
    iface = data.get('interface')

    try:
        return _synchronize_interfaces(device, interface=iface, test=test)
    except NetboxException as e:
        return False, e.data, e.message


@restful_method
def generate_interfaces(method, data):

    if not data.get('device'):
        return False, None, 'No device selected'

    device= data.get('device').upper()
    iface = data.get('interface')

    try:
        data = _generate_interfaces(device, in_name=iface)
    except NetboxException as e:
        return False, { 'api_url': e.url, 'code': e.code }, e.message

    return True, data, 'Interfaces generated from Netbox datasource for %s' % device
