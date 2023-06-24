import requests, json, logging, time, yaml, ipaddress, re
from copy import deepcopy
from config import netbox
from util import synchronizers

_DATASOURCE = netbox.NETBOX_SOURCE['name']

# Supported vyos if types
_VYOS_VLAN  = "^(eth|bond)([0-9]{1,3})(\.)([0-9]{1,4})$"
_VYOS_ETH   = "^(eth)([0-9]{1,3})$"
_VYOS_LAG   = "^(bond)([0-9]{1,3})$"
_VYOS_TUN   = "^(tun)([0-9]{1,3})$"
_VYOS_DUM   = "^(dum)([0-9]{1,3})$"

_TYPE_DICT = {
        'eth'    :  re.compile(_VYOS_ETH),
        'gre'    :  re.compile(_VYOS_TUN),
        'l2gre'  :  re.compile(_VYOS_TUN),
        'vlan'   :  re.compile(_VYOS_VLAN),
        'lacp'   :  re.compile(_VYOS_LAG),
        'dummy'  :  re.compile(_VYOS_DUM),
        }

# Used to verify parent interfaces for tunnels
_VYOS_PARENT  = "^(eth|bond)([0-9]{1,3})(?:(\.)([0-9]{1,4})){0,1}$"

logger = logging.getLogger(__name__)

class NetboxAPI:
    _API_BASE = netbox.NETBOX_URL + '/api'

    _PUBLIC_API_BASE = netbox.NETBOX_PUBLIC_URL

    _HEADERS = netbox.NETBOX_HEADERS

    _GRAPHQL_BASE = netbox.NETBOX_URL + '/graphql/'

    ENDPOINTS = {}
    
    def __init__(self, endpoint=None):
        self.set(endpoint)


    def set(self, endpoint):
        self.url = self._API_BASE
        self.public_url = self._PUBLIC_API_BASE

        if endpoint:
            if endpoint in self.ENDPOINTS.keys():
                endpoint = self.ENDPOINTS[endpoint]

            if not endpoint.startswith('/'):
                self.url += '/'
                self.public_url += '/'
            if not endpoint.endswith('/'):
                endpoint += '/'

            self.url += endpoint
            self.public_url += endpoint

        return self


    def set_url(self, url):
        self.url = url
        return self


    def set_id(self, id):
        self.url += str(id) + '/'
        self.public_url += str(id) + '/'
        return self


    def set_suffix(self, suffix):
        self.url += str(suffix) + '/'
        self.public_url += str(suffix) + '/'
        return self


    def set_params(self, **kwargs):
        suffix = '?'

        tags = kwargs.pop('tags', None)

        for k, v in kwargs.items():
            if v:
                suffix += '%s=%s&' % (k, v)

        if tags:
            if isinstance(tags, list):
                for tag in tags:
                    suffix += 'tag=%s&' % tag
            else:
                suffix += 'tag=%s' % tags

        # clean up url suffix
        if suffix.endswith('?') or suffix.endswith('&'):
            suffix = suffix[:-1]

        self.url += suffix
        self.public_url += suffix

        return self


    def get_url(self):
        return self.url


    def get_public_url(self):
        return self.public_url


    def get(self):
        url = self.url
        logger.debug(f'Netbox.get: {url}')
        resp = requests.get(url, headers = self._HEADERS)
        
        if (code := resp.status_code) not in [200, 404]:
            raise NetboxException(url, resp.json(), code)

        if 'results' in ( json := resp.json() ):
            return json['results']
        return json


    def post(self, data):
        url = self.url
        logger.debug(f'NetboxAPI.post: {url}')

        if data:
            resp = requests.post(url, headers = self._HEADERS, json = data )
        else:
            resp = requests.post(url, headers = self._HEADERS)

        code = resp.status_code

        result = False
        if code in range(200, 300):
            result = True

        if isinstance(resp, dict):
            out = resp.json()
        else:
            out = None

        return result, out


    def call_script(self, data):
        url = self.url
        logger.debug(f'NetboxAPI.call_script: {url}')
        resp = requests.post(url, headers = self._HEADERS, json = data )

        if 'results' in ( js := resp.json() ):
            return js['results']

        return js['result'] if 'result' in js else js


    def gql(self, query):
        url = self._GRAPHQL_BASE
        resp = requests.post(url, headers=self._HEADERS, json={"query": query})
        logger.debug(f'Netbox.gql: {url} {query}')

        if (code := resp.status_code) != 200:
            raise NetboxException(url, resp.json(), code)

        return resp.json()


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


def script_runner(script, data={}, commit=False):
    """ 
    Used to run netbox scripts, poll the job for set number of seconds, and
    then return output from the job result. 

    Uses data prepared by public methods. Expects yaml formatted output.
    """
    nb = NetboxAPI('extras/scripts').set_suffix(script)

    print(nb.get_url())

    result = nb.call_script({ 'data': data, 'commit': commit })

    # Location of the script's job
    url = result['url']
    nb.set_url(url)

    # Will continue to poll for 40 seconds before giving up.
    time_bank = 40

    # Errors tend to return quickly so first poll is after 2 seconds.
    step = 2
    out = None
    while time_bank > 0:
        time.sleep(step)
        ret = nb.get()
        status = ret['status'].get('value')

        if status == 'completed':
            out = yaml.safe_load(ret['data']['output'])
            break

        elif status == 'errored':
            out = {
                    'result'  : False,
                    'comment' : 'Netbox script encountered a runtime error',
                    'out'     : {
                        script : {
                            'jid'    : ret.get('job_id'),
                            'status' : status,
                            'url'    : url,
                            }
                        }
                    }
            break

        time_bank -= step

        # Increase polling time to 7 seconds.
        step = 7

    if not out:
        out = {
                'result'  : False,
                'comment' : 'Netbox script has not yet completed.',
                'out'     : {
                    script : {
                        'jid'    : ret.get('job_id'),
                        'status' : status,
                        'url'    : url,
                        }
                    }
                }

    # Empty result set means that there was nothing to be done. Return the
    # the relevant log failure / warning message.
    if not out.get('result') or not out.get('out'):
        return False, out.get('out'), out['comment']

    if commit:
        return True, out.get('out'), out['comment']

    return True, out.get('out'), 'Dry Run: Database changes have been reverted automatically.'


def generate_devices():
    ret = NetboxAPI().gql(netbox.DEVICE_GQL)

    def _get_ip(device, tag):
        for iface in device['loopbacks']:
            for ip in iface['ip_addresses']:
                for t in ip['tags']:
                    if t['name'] == tag:
                        return ip['address'].split('/')[0]

    def _gen_roles(device):
        roles = []
        if r := device['site']['custom_fields'].get('netdb_roles'):
            roles = r
        try:
            r = device['device_role']['custom_fields']['netdb_roles']
        except KeyError:
            return roles

        for i in r:
            if i not in roles:
                roles.append(i)

        return roles

    def _gen_providers(device):
        providers = []

        for port in device['wan_ports']:
            # Physical upstreams (such as MyRepublic) use traditional circuits in Netbox.
            for peer in port['link_peers']:
                if circuit := peer.get('circuit'):
                    if provider := circuit.get('provider'):
                        if ( slug := provider['slug'] ) not in providers:
                            providers.append(slug)

            # Upstreams in cloud providers (such as Vultr) are marked as VXLAN EXPN type
            # L2VPNs in Netbox.
            for termination in port['l2vpn_terminations']:
                if l2vpn := termination.get('l2vpn'):
                    if ( slug := l2vpn['slug'] ) not in providers:
                        providers.append(slug)

        return providers
    
    out = {}
    if ret['data']:
        for device in ret['data']['device_list']:
            if ( device['site']['status'].lower() not in ['active', 'staging', 'decommissioning']
                    or device['status'].lower() not in ['active', 'staged'] ):
                continue

            url = NetboxAPI('dcim/devices').set_id(device['id']).get_public_url()

            entry = {
                    'location'   : device['site']['region']['slug'],
                    'roles'      : _gen_roles(device),
                    'providers'  : _gen_providers(device),
                    'datasource' : _DATASOURCE,
                    'weight'     : netbox.NETBOX_SOURCE['weight'],
                    }

            meta = {
                    'netbox': {
                        'id'           : int(device['id']),
                        'url'          : url,
                        'status'       : device['status'],
                        'last_updated' : device['last_updated'],
                        },
                    }
            entry['meta'] = meta

            cvars = {
                    'ibgp_ipv4' : _get_ip(device, 'ibgp_ipv4'),
                    'ibgp_ipv6' : _get_ip(device, 'ibgp_ipv6'),
                    'iso'       : device['custom_fields']['iso_address'],
                    'router_id' : device['custom_fields']['router_id'],
                    'local_asn' : device['site']['asns'][0]['asn'],
                    }
            entry['cvars'] = { k : v for k, v in cvars.items() if v }
            out[ device['name'] ] = { k : v for k, v in entry.items() if v }

    return out


def generate_interfaces():
    ret = NetboxAPI().gql(netbox.IFACE_GQL)

    out = {}
    if ret['data']:
        interfaces  = ret['data'].get('interface_list')
        fw_contexts = ret['data'].get('config_context_list')

        for interface in interfaces:
            device = interface['device']['name']

            name = interface['name']
            type = interface['type']
            tags = [ i['name'] for i in interface['tags'] ]

            url = NetboxAPI('dcim/interfaces').set_id(interface['id']).get_public_url()

            # unmanaged / decom / hypervisor tagged interfaces are ignored
            if 'unmanaged' in tags or 'decom' in tags or 'hypervisor' in tags:
                continue

            meta =  {
                    'netbox' : {
                        'id'           : int(interface['id']),
                        'url'          : url,
                        'last_updated' : interface['last_updated'],
                        },
                    }

            entry = {
                    'meta'        : meta,
                    'mtu'         : interface['mtu'],
                    'description' : interface['description'],
                    'datasource'  : _DATASOURCE,
                    'weight'      : netbox.NETBOX_SOURCE['weight'],
                    }

            if not interface['enabled']:
                entry['disabled'] = True

            if route_policy := interface['custom_fields'].get('route_policy'):
                entry['policy'] = { 'ipv4' : route_policy, }

            addrs = {}
            for address in interface['ip_addresses']:
                url = NetboxAPI('ipam/ip-addresses').set_id(address['id']).get_public_url()

                meta =  {
                        'netbox' : {
                            'id'           : int(address['id']),
                            'url'          : url,
                            'last_updated' : address['last_updated'],
                            },
                        'tags' : [
                            i['name']
                            for i in address['tags']
                            ],
                        }

                if ptr := address['dns_name']:
                    meta.update({
                        'dns' : { 'ptr' : ptr }
                        })

                addrs[ address['address'] ] = { 'meta' : meta }

            entry['address'] = addrs

            if type in netbox.NETBOX_ETHERNET:
                entry['type'] = 'ethernet'
                if mac := interface['mac_address']:
                    entry['mac_address'] = mac.lower()
                if interface['custom_fields'].get('offload'):
                    entry['offload'] = True

            elif type == 'DUMMY':
                entry['type'] = 'dummy'

            elif type == 'LAG':
                entry['type'] = 'lacp'

                lacp =  {
                        'rate'        : 'fast',
                        'min_links'   : 1,
                        'hash_policy' : 'layer2+3',
                        'members'     : [],
                    }

                if min_links := interface['custom_fields']['lacp_min_links']:
                    entry['lacp']['min_links'] = min_links

                if 'layer3+4' in tags:
                    lacp['hash_policy'] = 'layer3+4'

                for i in interfaces:
                    if i['lag'] and i['lag'].get('id') == interface['id']:
                        lacp['members'].append(i['name'])

                entry['lacp'] = lacp

            elif type == 'VLAN':
                entry['type'] = 'vlan'

                if not interface['untagged_vlan']:
                    raise NetboxException(
                            message = '%s %s: untagged VLAN ID is required' % (device, name)
                            )

                if not interface['parent']:
                    raise NetboxException(
                            message = '%s %s: parent interface required' % (device, name) 
                            )

                vlan =  {
                        'id'     : interface['untagged_vlan']['vid'],
                        'parent' : interface['parent']['name'],
                        }

                entry['vlan'] = vlan

            elif type in ['GRE', 'L2GRE']:
                entry['type'] = type.lower()

                if ttl := interface['custom_fields']['ttl']:
                    entry['ttl'] = ttl

                # Get source IP and interface for tunnels
                if parent := interface['parent']:
                    if ips := parent['ip_addresses']:
                        for ip in ips:
                            if 'tun_src' in [ i['name'] for i in ip['tags'] ]:
                                entry['source'] = ip['address'].split('/')[0]
                                break

                    if interface['custom_fields']['bind_parent']:
                        entry['interface'] = parent['name']

                # Get GRE remote IP address
                if remote := interface['custom_fields'].get('remote_override'):
                    # The remote_override has been set. Use that.
                    entry['remote'] = remote
                elif vl := interface['virtual_link']:
                    # Otherwise use the tagged interface IP on the other end of the virtual link.
                    if vl['interface_a'].get('id') == interface['id']:
                        peer = vl['interface_b']
                    else:
                        peer = vl['interface_a']

                    if parent := peer['parent']:
                        if ips := parent['ip_addresses']:
                            for ip in ips:
                                if 'tun_src' in [ i['name'] for i in ip['tags'] ]:
                                    entry['remote'] = ip['address'].split('/')[0]
                                    break

                    # load tunnel key if set
                    if key := vl['custom_fields']['tunnel_key']:
                        entry['key'] = key

                    # if virtual link is not marked as connected then disable.
                    if vl['status'] != 'CONNECTED':
                        entry['disabled'] = True

            else:
                raise NetboxException( message = '%s: invalid type for %s' % (device, name) )

            # Load firewall rules based on tag join on interfaces and config_contexts.
            # TBD: Order loads by weight.
            for context in fw_contexts:
                for tag in tags:
                    if tag.startswith("fw_") and tag in [ i['name'] for i in context['tags'] ]:
                        if not entry.get('firewall'):
                            entry['firewall'] = {}
                        entry['firewall'].update(json.loads(context['data']))

            if not out.get(device):
                out[device] = {}

            out[device][name] = { k : v for k, v in entry.items() if v }

    return out


def generate_igp():
    ret = NetboxAPI().gql(netbox.IGP_GQL)

    out = {}
    if ret['data']:
        devices  = ret['data'].get('devices')
        contexts = ret['data'].get('contexts')

        for device in devices:
            name = device['name']

            entry = {
                    'weight'     : netbox.NETBOX_SOURCE['weight'],
                    'datasource' : _DATASOURCE,
                    'meta'       : {}
                    }

            # Load base config for this device.
            success = False
            for context in contexts:
                for role in context.get('roles'):
                    if role['id'] == device['device_role'].get('id'):
                        if data := json.loads(context['data']):
                            entry.update(data['isis'])
                            entry['meta']['netbox'] = {
                                    'name'         : context['name'],
                                    'last_updated' : context['last_updated'],
                                    }

                            success = True
                            break

            # Base config not found for this device.
            if not success:
                continue

            interfaces = []
            for status in ['active', 'passive']:
                for interface in device[status]:
                    iface = {
                            'name' : interface['name'],
                            }
                    if status == 'passive':
                        iface[status] = 'y'

                    interfaces.append(iface)

            isis =  {
                    'interfaces' : interfaces,
                    'iso'        : device['custom_fields'].get('iso_address'),
                    }
            entry.update(isis)

            out[name] = { 'isis': entry }

    return out


def generate_ebgp():
    ret = NetboxAPI().gql(netbox.EBGP_GQL)

    out = {}
    if ret['data']:
        devices = ret['data'].get('devices')

        for device in devices:
            device_name = device['name']

            try:
                bgp_peers = device['config_context']['bgp']['peers']
            except KeyError:
                continue
                
            neighbors = {}
            for interface in device['ebgp_interfaces']:
                iface_tags = [ i['name'] for i in interface['tags'] ]

                # unmanaged / decom / hypervisor tagged interfaces are ignored
                if 'unmanaged' in iface_tags or 'decom' in iface_tags or 'hypervisor' in iface_tags:
                    continue

                # "unwired" interfaces are ignored
                if not (vl := interface.get('virtual_link')):
                    continue

                # if virtual link is not marked as connected then ignore.
                if vl['status'] != 'CONNECTED':
                    continue

                if vl['interface_a'].get('id') == interface['id']:
                    my_iface   = vl['interface_a']
                    peer_iface = vl['interface_b']
                else:
                    my_iface   = vl['interface_b']
                    peer_iface = vl['interface_a']

                try:
                    peer_asn = peer_iface['device']['site']['asns'][0]['asn']
                except KeyError:
                    # Peer peer_iface or peer_asn not found; ignore this interface.
                    continue

                if not (bgp_peer := bgp_peers.get(peer_asn)):
                    if not (bgp_peer := bgp_peers.get(str(peer_asn))):
                        # No peer entry found in config context; ignore this interface.
                        continue

                for ip in peer_iface['ip_addresses']:
                    ip_tags = [ i['name'] for i in ip['tags'] ]

                    if 'prune' in ip_tags or 'decom' in ip_tags:
                        # IPs marked for removal are ignored.
                        continue

                    try:
                        peer_group = bgp_peer[ ip['family']['label'].lower() ]['peer_group']
                    except KeyError:
                        # No peer group defined for this address family. continue.
                        continue

                    neighbor = {
                            'peer_group' : peer_group,
                            'datasource' : _DATASOURCE,
                            'weight'     : netbox.NETBOX_SOURCE['weight'],
                            }
                    neighbors[ str(ip['address']).split('/')[0] ] = neighbor

            if neighbors:
                out[device_name] = {}
                out[device_name]['neighbors'] = neighbors
    return out


def synchronize_devices(test = True):
    netbox_dev = generate_devices()

    return synchronizers.devices(_DATASOURCE, netbox_dev, test)


def synchronize_interfaces(test=True):
    netbox_ifaces = generate_interfaces()

    return synchronizers.interfaces(_DATASOURCE, netbox_ifaces, test)


def synchronize_igp(test = True):
    netbox_igp = generate_igp()

    return synchronizers.igp(_DATASOURCE, netbox_igp, test)


def synchronize_ebgp(test=True):
    netbox_ebgp = generate_ebgp()

    return synchronizers.bgp_sessions(_DATASOURCE, netbox_ebgp, test)
