import requests, json, logging, time, yaml, ipaddress, re
from copy import deepcopy
from util import netdb
from util.django_api import DjangoAPI
from util.exception import UtilityAPIException
from util import netbox_resources as netbox
from config.defaults import NETBOX_SOURCE
from config.secrets import NETBOX_TOKEN, NETBOX_URL, NETBOX_PUBLIC_URL

_DEVICES_COLUMN = 'device'
_IFACES_COLUMN = 'interface'
_IGP_COLUMN = 'igp'
_BGP_COLUMN = 'bgp'

NETBOX_HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': 'Token ' + NETBOX_TOKEN,
}

# Supported vyos if types
_VYOS_VLAN = "^(eth|bond)([0-9]{1,3})(\.)([0-9]{1,4})$"
_VYOS_ETH = "^(eth)([0-9]{1,3})$"
_VYOS_LAG = "^(bond)([0-9]{1,3})$"
_VYOS_TUN = "^(tun)([0-9]{1,3})$"
_VYOS_DUM = "^(dum)([0-9]{1,3})$"

_TYPE_DICT = {
    'eth': re.compile(_VYOS_ETH),
    'gre': re.compile(_VYOS_TUN),
    'l2gre': re.compile(_VYOS_TUN),
    'vlan': re.compile(_VYOS_VLAN),
    'lacp': re.compile(_VYOS_LAG),
    'dummy': re.compile(_VYOS_DUM),
}

# Used to verify parent interfaces for tunnels
_VYOS_PARENT = "^(eth|bond)([0-9]{1,3})(?:(\.)([0-9]{1,4})){0,1}$"

logger = logging.getLogger(__name__)


def _container(data):
    return {
        'column': data,
        **NETBOX_SOURCE,
    }


class NetboxException(UtilityAPIException):
    pass


class NetboxAPI(DjangoAPI):
    """
    Simple class for interacting with Netbox API and GQL endpoint.
    """

    _API_BASE = NETBOX_URL + '/api'

    _PUBLIC_API_BASE = NETBOX_PUBLIC_URL

    _HEADERS = NETBOX_HEADERS

    _GRAPHQL_BASE = NETBOX_URL + '/graphql/'

    _ERR_MSG = 'Netbox API returned an error'

    def call_script(self, data):
        url = self.url
        logger.debug(f'NetboxAPI.call_script: {url}')
        resp = requests.post(url, headers=self._HEADERS, json=data)

        if resp.status_code in range(500, 600):
            # It's really borked. Don't even try to extract and return json.
            raise NetboxException(url=url, code=resp.status_code, message=resp.reason)

        data = resp.json()

        if resp.status_code != 200:
            raise NetboxException(url=url, code=resp.status_code, data=data)

        if ret := data.get('results'):
            return data

        return data.get('result') or data

    def gql(self, query):
        url = self._GRAPHQL_BASE
        resp = requests.post(url, headers=self._HEADERS, json={"query": query})
        logger.debug(f'Netbox.gql: {url} {query}')

        if resp.status_code in range(500, 600):
            raise NetboxException(url=url, code=resp.status_code, message=resp.reason)

        if resp.status_code != 200:
            raise NetboxException(url=url, code=resp.status_code, data=resp.json())

        return resp.json()


class NetboxConnector:
    def __init__(self, test=False):
        self.test = test
        self.nb_api = NetboxAPI()

    def script_runner(self, script, data={}):
        """
        Used to run netbox scripts, poll the job for set number of seconds, and
        then return output from the job result.

        Uses data prepared by public methods. Expects yaml formatted output.
        """
        commit = not self.test

        self.nb_api.set('extras/scripts').set_suffix(script)

        result = self.nb_api.call_script({'data': data, 'commit': commit})

        # Location of the script's job
        if not (url := result.get('url')):
            return False, result, 'Major script error!'
        self.nb_api.set_url(url)

        # Will continue to poll for 40 seconds before giving up.
        time_bank = 40

        # Errors tend to return quickly so first poll is after 2 seconds.
        step = 2
        out = None
        while time_bank > 0:
            time.sleep(step)

            # DjangoAPI objects cache get responces. Clear this cache before polling.
            self.nb_api.clear_cache()
            ret = self.nb_api.get()
            status = ret['status'].get('value')

            if status == 'completed':
                out = yaml.safe_load(ret['data']['output'])
                break

            elif status == 'errored':
                raise NetboxException(
                    code=400,
                    message='Netbox script encountered a runtime error',
                    data={
                        script: {
                            'jid': ret.get('job_id'),
                            'status': status,
                            'url': url,
                        }
                    },
                )

            time_bank -= step

            # Increase polling time to 7 seconds.
            step = 7

        if not out:
            raise NetboxException(
                code=404,
                message='Netbox script has not yet completed.',
                data={
                    script: {
                        'jid': ret.get('job_id'),
                        'status': status,
                        'url': url,
                    }
                },
            )

        return out

    def generate_devices(self):
        ret = self.nb_api.gql(netbox.DEVICE_GQL)

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
                            if (slug := provider['slug']) not in providers:
                                providers.append(slug)

                # Upstreams in cloud providers (such as Vultr) are marked as VXLAN EXPN type
                # L2VPNs in Netbox.
                for termination in port['l2vpn_terminations']:
                    if l2vpn := termination.get('l2vpn'):
                        if (slug := l2vpn['slug']) not in providers:
                            providers.append(slug)

            return providers

        out = {}

        if ret['data']:
            for device in ret['data']['device_list']:
                if device['site']['status'].lower() not in [
                    'active',
                    'staging',
                    'decommissioning',
                ] or device['status'].lower() not in ['active', 'staged']:
                    continue

                url = NetboxAPI('dcim/devices').set_id(device['id']).get_public_url()

                entry = {
                    'location': device['site']['region']['slug'],
                    'roles': _gen_roles(device),
                    'providers': _gen_providers(device),
                    'node_name': device['name'],
                }

                meta = {
                    'netbox': {
                        'id': int(device['id']),
                        'url': url,
                        'status': device['status'],
                        'last_updated': device['last_updated'],
                    },
                }
                entry['meta'] = meta

                cvars = {
                    'ibgp_ipv4': _get_ip(device, 'ibgp_ipv4'),
                    'ibgp_ipv6': _get_ip(device, 'ibgp_ipv6'),
                    'iso': device['custom_fields']['iso_address'],
                    'router_id': device['custom_fields']['router_id'],
                    'local_asn': device['site']['asns'][0]['asn'],
                    'primary_ipv4': device['primary_ip4']['address'].split('/')[0],
                    'primary_ipv6': device['primary_ip6']['address'].split('/')[0],
                    'primary_contact': device['contacts'][0]['contact']['email'],
                }
                entry['cvars'] = {k: v for k, v in cvars.items() if v}
                out[device['name']] = {k: v for k, v in entry.items() if v}
        else:
            return None

        return out

    def generate_interfaces(self):
        ret = self.nb_api.gql(netbox.IFACE_GQL)

        out = {}

        if ret['data']:
            interfaces = ret['data'].get('interface_list')
            fw_contexts = ret['data'].get('config_context_list')

            for interface in interfaces:
                device = interface['device']['name']

                name = interface['name']
                type = interface['type']
                tags = [i['name'] for i in interface['tags']]

                url = (
                    NetboxAPI('dcim/interfaces')
                    .set_id(interface['id'])
                    .get_public_url()
                )

                # unmanaged / decom / hypervisor tagged interfaces are ignored
                if 'unmanaged' in tags or 'decom' in tags or 'hypervisor' in tags:
                    continue

                meta = {
                    'netbox': {
                        'id': int(interface['id']),
                        'url': url,
                        'last_updated': interface['last_updated'],
                    },
                }

                entry = {
                    'meta': meta,
                    'mtu': interface['mtu'],
                    'description': interface['description'],
                    'vrf': (interface.get('vrf') or {}).get('name'),
                    'use_dhcp': bool(interface['custom_fields'].get('use_dhcp')),
                }

                if not interface['enabled']:
                    entry['disabled'] = True

                if route_policy := interface['custom_fields'].get('route_policy'):
                    entry['policy'] = {
                        'ipv4': route_policy,
                    }

                addrs = {}
                for address in interface['ip_addresses']:
                    url = (
                        NetboxAPI('ipam/ip-addresses')
                        .set_id(address['id'])
                        .get_public_url()
                    )

                    meta = {
                        'netbox': {
                            'id': int(address['id']),
                            'url': url,
                            'last_updated': address['last_updated'],
                        },
                        'tags': [i['name'] for i in address['tags']],
                    }

                    if ptr := address['dns_name']:
                        meta.update({'dns': {'ptr': ptr}})

                    addrs[address['address']] = {'meta': meta}

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

                    lacp = {
                        'rate': 'fast',
                        'min_links': 1,
                        'hash_policy': 'layer2+3',
                        'members': [],
                    }

                    if min_links := interface['custom_fields'].get('lacp_min_links'):
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
                            message=f'{device} {name}: untagged VLAN ID is required'
                        )

                    if not interface['parent']:
                        raise NetboxException(
                            message=f'{device} {name}: parent interface required'
                        )

                    vlan = {
                        'id': interface['untagged_vlan']['vid'],
                        'parent': interface['parent']['name'],
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
                                if 'tun_src' in [i['name'] for i in ip['tags']]:
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
                                    if 'tun_src' in [i['name'] for i in ip['tags']]:
                                        entry['remote'] = ip['address'].split('/')[0]
                                        break

                        # load tunnel key if set
                        if key := vl['custom_fields']['tunnel_key']:
                            entry['key'] = key

                        # if virtual link is not marked as connected then disable.
                        if vl['status'] != 'CONNECTED':
                            entry['disabled'] = True

                else:
                    raise NetboxException(message=f'{device}: invalid type for {name}')

                # Load firewall rules based on tag join on interfaces and config_contexts.
                # TBD: Order loads by weight.
                for context in fw_contexts:
                    for tag in tags:
                        if tag.startswith("fw_") and tag in [
                            i['name'] for i in context['tags']
                        ]:
                            if not entry.get('firewall'):
                                entry['firewall'] = {}
                            entry['firewall'].update(json.loads(context['data']))

                if not out.get(device):
                    out[device] = {}

                out[device][name] = {k: v for k, v in entry.items() if v}
        else:
            return None

        return out

    def generate_igp(self):
        ret = self.nb_api.gql(netbox.IGP_GQL)

        out = {}

        if ret['data']:
            devices = ret['data'].get('devices')
            contexts = ret['data'].get('contexts')

            for device in devices:
                name = device['name']

                entry = {'meta': {}}

                # Load base config for this device.
                success = False
                for context in contexts:
                    for role in context.get('roles'):
                        if role['id'] == device['device_role'].get('id'):
                            if data := json.loads(context['data']):
                                entry.update(data['isis'])
                                entry['meta']['netbox'] = {
                                    'name': context['name'],
                                    'last_updated': context['last_updated'],
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
                            'name': interface['name'],
                        }
                        if status == 'passive':
                            iface[status] = 'y'

                        interfaces.append(iface)

                isis = {
                    'interfaces': interfaces,
                    'iso': device['custom_fields'].get('iso_address'),
                }
                entry.update(isis)

                out[name] = {'isis': entry}
        else:
            return None

        return out

    def generate_ebgp(self):
        ret = self.nb_api.gql(netbox.EBGP_GQL)

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
                    iface_tags = [i['name'] for i in interface['tags']]

                    # unmanaged / decom / hypervisor tagged interfaces are ignored
                    if (
                        'unmanaged' in iface_tags
                        or 'decom' in iface_tags
                        or 'hypervisor' in iface_tags
                    ):
                        continue

                    # "unwired" interfaces are ignored
                    if not (vl := interface.get('virtual_link')):
                        continue

                    # if virtual link is not marked as connected then ignore.
                    if vl['status'] != 'CONNECTED':
                        continue

                    if vl['interface_a'].get('id') == interface['id']:
                        my_iface = vl['interface_a']
                        peer_iface = vl['interface_b']
                    else:
                        my_iface = vl['interface_b']
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
                        ip_tags = [i['name'] for i in ip['tags']]

                        if 'prune' in ip_tags or 'decom' in ip_tags:
                            # IPs marked for removal are ignored.
                            continue

                        try:
                            peer_group = bgp_peer[ip['family']['label'].lower()][
                                'peer_group'
                            ]
                        except KeyError:
                            # No peer group defined for this address family. continue.
                            continue

                        neighbor = {
                            'peer_group': peer_group,
                        }
                        neighbors[str(ip['address']).split('/')[0]] = neighbor

                if neighbors:
                    out[device_name] = {}
                    out[device_name]['neighbors'] = neighbors
        else:
            return None

        return out

    def reload_devices(self):
        data = self.generate_devices()

        return netdb.reload(_DEVICES_COLUMN, _container(data))

    def reload_interfaces(self):
        data = self.generate_interfaces()

        return netdb.reload(_IFACES_COLUMN, _container(data))

    def reload_igp(self):
        data = self.generate_igp()

        return netdb.reload(_IGP_COLUMN, _container(data))

    def reload_ebgp(self):
        data = self.generate_ebgp()

        return netdb.reload(_BGP_COLUMN, _container(data))
