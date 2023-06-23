import requests, json, logging, time, yaml, ipaddress
from marshmallow import ValidationError
from copy import deepcopy
from util.decorators import restful_method
from config import pm
from schema import pm as pm_schema
from util import synchronizers

# Public symbols
__all__ = [
        'generate_direct_sessions',
        'generate_ixp_sessions',
        'generate_session',
        'synchronize_sessions',
        'synchronize_session',
        'set_status',
        'create_policy',
        'delete_policy',
        'create_asn',
        'peeringdb_asn_sync',
        ]

_DATASOURCE = pm.PM_SOURCE['name']

_DEFAULT_REJECT = 'REJECT-ALL'

logger = logging.getLogger(__name__)

class PeeringManager:
    """
    Simple class for interacting with Peering Manager API.
    """
    _API_BASE = pm.PM_URL + '/api'

    _PUBLIC_API_BASE = pm.PM_PUBLIC_URL + '/api'

    _HEADERS = pm.PM_HEADERS

    ENDPOINTS = {
        'direct-sessions' : 'peering/direct-peering-sessions',
        'ixp-sessions'    : 'peering/internet-exchange-peering-sessions',
        'policies'        : 'peering/routing-policies',
        'groups'          : 'peering/bgp-groups',
        'asns'            : 'peering/autonomous-systems',
        'ixps'            : 'peering/internet-exchanges',
        'policies'        : 'peering/routing-policies',
        'connections'     : 'net/connections',
        }

    def __init__(self, endpoint=None):
        self.set(endpoint)


    def set(self, endpoint):
        self.url = self._API_BASE
        self.public_url = self._PUBLIC_API_BASE

        if endpoint in self.ENDPOINTS.keys():
            endpoint = self.ENDPOINTS[endpoint]

        if endpoint:
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


    def get_public_url(self):
        return self.public_url


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

        logger.debug(f'PM.get: {url}')
        resp = requests.get(url, headers = self._HEADERS)
        
        if (code := resp.status_code) not in [200, 404]:
            raise PMException(url, resp.json(), code)

        if 'results' in ( json := resp.json() ):
            return json['results']
        return json


    def post(self, data=None):
        url = self.url
        logger.debug(f'PM.get: {url}')

        if data:
            resp = requests.post(url, headers = self._HEADERS, json = data)
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


    def patch(self, data):
        url = self.url
        logger.debug(f'PM.patch: {url}')
        resp = requests.patch(url, headers = self._HEADERS, json = data )
        code = resp.status_code

        result = False
        if code in range(200, 300):
            result = True

        return result, resp.json()


    def delete(self):
        url = self.url
        logger.debug(f'PM.patch: {url}')
        resp = requests.delete(url, headers = self._HEADERS)
        code = resp.status_code

        result = False
        if code in range(200, 300):
            result = True

        return result


class PMException(Exception):
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


def _search_direct_sessions(device, ip):
    try:
        ipaddress.ip_address(ip)
    except:
        return None

    sessions = PeeringManager('direct-sessions').get(q=ip)

    for session in sessions:
        if ( session['router'].get('name') == device 
                and session.get('ip_address').split('/')[0] == ip ):
            return session.get('id')

    return None


def _search_ixp_sessions(device, ip):
    try:
        ipaddress.ip_address(ip)
    except:
        return None

    sessions = PeeringManager('ixp-sessions').get(q=ip)
    connections = { i.pop('id') : i for i in PeeringManager('connections').get() }

    for session in sessions:
        connection_id = session['ixp_connection'].get('id')
        if ( connections[connection_id]['router'].get('name') == device
                and session.get('ip_address') == ip ):
            return session.get('id')

    return None


def _search_policies(name):
    policies = PeeringManager('policies').get(q=name)

    for policy in policies:
        if policy.get('name') == name:
            return policy.get('id')

    return None


def _search_asns(number):
    asns = PeeringManager('asns').get(q=number)

    for asn in asns:
        if asn.get('asn') == number:
            return asn.get('id')

    return None


def _create_policy(data):
    data_in = { k: v for k, v in data.items() if v }

    try:
        policy = pm_schema.PolicySchema().load(data_in)
    except ValidationError as error:
        return False, error.messages, 'invalid policy data'

    result, ret = PeeringManager('policies').post(policy)

    msg = 'PM API returned an error'
    if result:
        msg = 'Policy created'

    return result, ret, msg


def _delete_policy(name):
    id = _search_policies(name)
    if not id:
        return False, None, 'Policy not found in Peering Manager'

    result = PeeringManager('policies').set_id(id).delete()

    msg = 'PM API returned an error'
    if result:
        msg = 'Policy deleted'

    return result, None, msg


def _generate_policies(pm_object, policies, family):
    # ASN / IXP etc.  policies for v4 and v6 groups together. We need to tease out the policies
    # for our family.
    policy_ids = {
            'import' : [ i['id'] for i in pm_object['import_routing_policies'] ],
            'export' : [ i['id'] for i in pm_object['export_routing_policies'] ],
            }

    out_policies = {}
    for i in ['import_routing_policies', 'export_routing_policies']:
        generated = []
        for j in policy_ids[ i.split('_')[0] ]:
            if policies[j]['address_family'] in [0, family]:
                generated.append(policies[j]['name'])

        if generated:
            out_policies[i] = generated

    return out_policies


def _create_asn(data):
    data_in = { k: v for k, v in data.items() if v }

    try:
        asn = pm_schema.AsnSchema().load(data_in)
    except ValidationError as error:
        return False, error.messages, 'invalid ASN data'

    result, ret = PeeringManager('asns').post(asn)

    msg = 'PM API returned an error'
    if result:
        msg = 'ASN created'

    return result, ret, msg


def _peeringdb_asn_sync(name):
    id = _search_asns(name)
    if not id:
        return False, None, 'ASN not found in Peering Manager'

    result, _  = PeeringManager('asns').set_id(id).set_suffix('sync-with-peeringdb').post()

    msg = 'PM API returned an error'
    if result:
        msg = 'ASN synchronized from peeringdb'

    return result, None, msg


def _delete_asn(name):
    id = _search_asns(name)
    if not id:
        return False, None, 'ASN not found in Peering Manager'

    result = PeeringManager('asns').set_id(id).delete()

    msg = 'PM API returned an error'
    if result:
        msg = 'ASN deleted'

    return result, None, msg


def _generate_direct_session_base(session, groups, asns, policies):
    if ( status := session['status'].get('value') ) == 'disabled':
        return None

    session_id = int(session['id'])

    group = {}
    group_id = None
    if g := session.get('bgp_group'):
        group = groups[ g['id'] ]
        group_id = int(g['id'])

        if ( s := group['status'].get('value') ) == 'disabled':
            return None

        # a group status of maintenance overrides session status.
        if s == 'maintenance':
            status = s

    tags = [ i['name'] for i in session['tags'] ]
    if group:
        tags += [ i['name'] for i in group['tags'] ]

    device = session['router'].get('name')
    ip = session.get('ip_address').split('/')[0]

    if ipaddress.ip_address(ip).version == 6:
        family = 6
    else:
        family = 4

    url = f"{PeeringManager('direct-sessions').get_public_url()}{session_id}/"

    source_ip = session.get('local_ip_address')

    entry = {
            'remote_asn' : session['autonomous_system'].get('asn'),
            'multihop'   : session.get('multihop_ttl'),
            'password'   : session.get('password'),
            'source'     : source_ip.split('/')[0] if source_ip else None,
            'type'       : 'ebgp',
            'datasource' : _DATASOURCE,
            'weight'     : pm.PM_SOURCE['weight'],
             }

    if group and ( group_context := group.get('local_context_data') ):
        if timers := group_context.get('timers'):
            entry['timers'] = timers

    if local_context := session.get('local_context_data'):
        if timers := local_context.get('timers'):
            entry['timers'] = timers

    addr_fam  = { 'nhs' : 'y'}
    route_map = {}

    # Used for loading ASN level policies
    asn_id = session['autonomous_system']['id']
    asn = asns.get(asn_id)

    asn_policies = _generate_policies(asn, policies, family)

    for i in ['import_routing_policies', 'export_routing_policies']:
        if 'reject' in tags or status == 'maintenance':
            route_map[ i.split('_')[0] ] = _DEFAULT_REJECT
        elif len(session[i]) > 0:
            route_map[ i.split('_')[0] ] = session[i][0]['name']
        elif group and len(group[i]) > 0:
            route_map[ i.split('_')[0] ] = group[i][0]['name']
        elif asn_policies and len(asn_policies[i]) > 0:
            # If no session or group policies, we can try ASN
            route_map[ i.split('_')[0] ] = asn_policies[i][0]
        else:
            route_map[ i.split('_')[0] ] = _DEFAULT_REJECT

    addr_fam['route_map'] = route_map

    relationship = session['relationship'].get('slug')

    if relationship != 'transit-session':
        if family == 6:
            max_prefixes = session['autonomous_system'].get('ipv6_max_prefixes')
        else:
            max_prefixes = session['autonomous_system'].get('ipv4_max_prefixes')

        if max_prefixes:
            addr_fam['max_prefixes'] = max_prefixes

    meta = {
            'session_id'   : session_id,
            'url'          : url,
            'status'       : status,
            'tags'         : tags,
            'group'        : group.get('slug'),
            'group_id'     : group_id,
            'comments'     : session.get('comments'),
            'type'         : relationship,
            }
    meta = { k : v for k, v in meta.items() if v }

    entry.update({
        'meta'   : { 'peering_manager' : meta },
        'family' : { 'ipv' + str(family) : addr_fam },
        })

    return {
            'device' : device,
            'ip'     : ip,
            'data'   : { k : v for k, v in entry.items() if v },
            }


def _generate_ixp_session_base(session, connections, ixps, asns, policies):
    if ( status := session['status'].get('value') ) == 'disabled':
        return None

    session_id = int(session['id'])

    connection_id = session['ixp_connection']['id']
    connection = connections.get(connection_id)

    ixp_id = connection['internet_exchange_point']['id']
    ixp = ixps.get(ixp_id)

    if 'disabled' in [ connection['status'], ixp['status'] ]:
        return None

    if 'maintenance' in [ session['status'], connection['status'], ixp['status'] ]:
        status = 'maintenance'

    tags = [ i['name'] for i in (session['tags'] + connection['tags'] + ixp['tags']) ]

    device = connection['router'].get('name')
    ip = session.get('ip_address').split('/')[0]

    if ipaddress.ip_address(ip).version == 6:
        family = 6
    else:
        family = 4

    url = f"{PeeringManager('ixp-sessions').get_public_url()}{session_id}/"

    entry = {
            'remote_asn' : session['autonomous_system'].get('asn'),
            'password'   : session.get('password'),
            'type'       : 'ebgp',
            'datasource' : _DATASOURCE,
            'weight'     : pm.PM_SOURCE['weight'],
            }

    for g in [ session, connection, ixp ]:
        if context := g.get('local_context_data'):
            if timers := context.get('timers'):
                entry['timers'] = timers

    addr_fam  = { 'nhs' : 'y'}
    route_map = {}

    # Used for loading ASN level policies
    asn_id = session['autonomous_system']['id']
    asn = asns.get(asn_id)

    # Try to load policies for ASN
    ixp_asn_policies = _generate_policies(asn, policies, family)
    if not ixp_asn_policies:
        # No ASN policies found. Next try IXP.
        ixp_asn_policies = _generate_policies(ixp, policies, family)

    # Add policies to BGP entry
    for i in ['import_routing_policies', 'export_routing_policies']:
        if 'reject' in tags or status == 'maintenance':
            route_map[ i.split('_')[0] ] = _DEFAULT_REJECT
        elif len(session[i]) > 0:
            # Session policies have highest priority
            route_map[ i.split('_')[0] ] = session[i][0]['name']
        elif ixp_asn_policies and len(ixp_asn_policies[i]) > 0:
            # If no session policies, we can try ASN or IXP
            route_map[ i.split('_')[0] ] = ixp_asn_policies[i][0]
        else:
            route_map[ i.split('_')[0] ] = _DEFAULT_REJECT

    addr_fam['route_map'] = route_map

    if 'ix_transit' not in tags:
        if family == 6:
            max_prefixes = session['autonomous_system'].get('ipv6_max_prefixes')
        else:
            max_prefixes = session['autonomous_system'].get('ipv4_max_prefixes')

        if max_prefixes:
            addr_fam['max_prefixes'] = max_prefixes

    meta = {
            'session_id'    : session_id,
            'url'           : url,
            'status'        : status,
            'tags'          : tags,
            'ixp'           : ixp.get('slug'),
            'ixp_id'        : ixp_id,
            'connection_id' : ixp_id,
            'comments'      : session.get('comments'),
            'type'          : 'ixp-session',
            }
    meta = { k : v for k, v in meta.items() if v }

    entry.update({
        'meta'   : { 'peering_manager' : meta },
        'family' : { 'ipv' + str(family) : addr_fam },
        })

    return {
            'device' : device,
            'ip'     : ip,
            'data'   : { k : v for k, v in entry.items() if v },
            }


def _generate_direct_sessions():
    sessions = PeeringManager('direct-sessions').get()
    groups   = { i.pop('id') : i for i in PeeringManager('groups').get() }
    asns     = { i.pop('id') : i for i in PeeringManager('asns').get() }
    policies = { i.pop('id') : i for i in PeeringManager('policies').get() }

    out = {}
    if sessions:
        for session in sessions:
            result = _generate_direct_session_base(session, groups, asns, policies)
            if not result:
                continue

            if not out.get(result['device']):
                out[ result['device'] ] = { 'neighbors' : {} }
            out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']

    return out


def _generate_direct_session(id):
    session = PeeringManager('direct-sessions').set_id(id).get()

    groups = {}
    if session['bgp_group'] and ( group_id := session['bgp_group'].get('id') ):
        g = PeeringManager('groups').set_id(group_id).get()
        groups = { g.pop('id') : g }

    a = PeeringManager('asns').set_id(session['autonomous_system']['id']).get()
    asns = { a.pop('id') : a }

    policies = { i.pop('id') : i for i in PeeringManager('policies').get() }

    out = {}
    if session.get('id'):
        result = _generate_direct_session_base(session, groups, asns, policies)
        if not result:
            return None

        out[ result['device'] ] = { 'neighbors' : {} }
        out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']

    return out


def _generate_ixp_sessions():
    # No fancy scripts or graphql in PM so just need to load a lot of stuff.
    sessions    = PeeringManager('ixp-sessions').get()

    # Turn these into `id' keyed dicts for quick lookups. 
    connections = { i.pop('id') : i for i in PeeringManager('connections').get() }
    ixps        = { i.pop('id') : i for i in PeeringManager('ixps').get() }
    asns        = { i.pop('id') : i for i in PeeringManager('asns').get() }
    policies    = { i.pop('id') : i for i in PeeringManager('policies').get() }

    out = {}
    if sessions:
        for session in sessions:
            result = _generate_ixp_session_base(session, connections, ixps, asns, policies)
            if not result:
                continue

            if not out.get(result['device']):
                out[ result['device'] ] = { 'neighbors' : {} }
            out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']

    return out


def _generate_ixp_session(id):
    session = PeeringManager(f'ixp-sessions').set_id(id).get()

    c = PeeringManager('connections').set_id(session['ixp_connection']['id']).get()
    connections = { c.pop('id') : c}

    i = PeeringManager('ixps').set_id(c['internet_exchange_point']['id']).get()
    ixps = { i.pop('id') : i}

    a = PeeringManager('asns').set_id(session['autonomous_system']['id']).get()
    asns = { a.pop('id') : a }

    policies = { i.pop('id') : i for i in PeeringManager('peering/routing-policies').get() }

    out = {}
    if session.get('id'):
        result = _generate_ixp_session_base(session, connections, ixps, asns, policies)
        if not result:
            return None

        out[ result['device'] ] = { 'neighbors' : {} }
        out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']

    return out


def _generate_session(device, ip):
    out = None

    # Try direct sessions first
    if session_id := _search_direct_sessions(device, ip):
        out = _generate_direct_session(session_id)

    # No direct sessions found; try IXP session
    elif session_id := _search_ixp_sessions(device, ip):
        out = _generate_ixp_session(session_id)

    # No sessions found
    return out


def _synchronize_sessions(test=True):
    # Load and validation
    pm_sessions = _generate_ixp_sessions()
     
    # Pull direct sessions and merge them on top of IXP sessions.
    for session, neighbors in _generate_direct_sessions().items():
        if not pm_sessions.get(session):
            pm_sessions[session] = { 'neighbors' : {} }
        for neighbor, bgp_data in neighbors.get('neighbors').items():
            pm_sessions[session]['neighbors'][neighbor] = bgp_data


    return synchronizers.bgp_sessions(_DATASOURCE, pm_sessions, test)


def _synchronize_session(device, ip, test=True):
    # Load and validation
    pm_session = _generate_session(device, ip)

    return synchronizers.bgp_session(_DATASOURCE, pm_session, device, ip, test)


def _set_status(device, ip, status):
    if status not in ['enabled', 'disabled', 'maintenance']:
        return False, None, 'invalid session status'

    data = { 'status': status }

    # Try direct sessions first
    if session_id := _search_direct_sessions(device, ip):
        endpoint = f'peering/direct-peering-sessions/{session_id}/'

    # No direct sessions found; try IXP session
    elif session_id := _search_ixp_sessions(device, ip):
        endpoint = f'peering/internet-exchange-peering-sessions/{session_id}/'

    # No sessions found.
    else:
        return False, None, 'PM eBGP session not found.'

    session = PeeringManager(endpoint).get()
    if session['status'].get('value') == status:
        return False, None, 'Status not changed'

    PeeringManager(endpoint).patch(data)

    # Synchronize netdb and return
    return _synchronize_session(device, ip, test=False)


@restful_method
def generate_direct_sessions(method, data, params):
    try:
        data = _generate_direct_sessions()

    except PMException as e:
        logger.error(f'exception at pm.generate_direct_sessions: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'eBGP direct sessions generated from Peering Manager datasource'


@restful_method
def generate_ixp_sessions(method, data, params):
    try:
        data = _generate_ixp_sessions()

    except PMException as e:
        logger.error(f'exception at pm.generate_ixp_sessions: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'eBGP IXP sessions generated from Peering Manager datasource'


@restful_method
def generate_session(method, data, params):
    device = params.get('device')
    ip = params.get('ip')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    try:
        data = _generate_session(device, ip)

    except PMException as e:
        logger.error(f'exception at pm.generate_session: {e.message}', exc_info=e)
        return False, e.data, e.message

    msg = f'eBGP session not found'
    if data:
        msg = 'eBGP session generated from Peering Manager datasource'

    return bool(data), data, msg


@restful_method
def synchronize_sessions(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return _synchronize_sessions(test)
    except PMException as e:
        return False, e.data, e.message


@restful_method
def synchronize_session(method, data, params):
    device = params.get('device')
    ip = params.get('ip')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return _synchronize_session(device, ip, test)
    except PMException as e:
        return False, e.data, e.message


@restful_method(methods=['PUT'])
def set_status(method, data, params):
    device = params.get('device')
    ip = params.get('ip')
    status = params.get('status')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    try:
        return _set_status(device, ip, status)

    except PMException as e:
        logger.error(f'exception at pm.set_maintenance: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def create_policy(method, data, params):

    try:
        return _create_policy(data)

    except PMException as e:
        logger.error(f'exception at pm.create_policy: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['DELETE'])
def delete_policy(method, data, params):
    name = params.get('name')

    if not  isinstance(name, str):
        return False, None, 'name parameter required'

    try:
        return _delete_policy(name)

    except PMException as e:
        logger.error(f'exception at pm.delete_policy: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def create_asn(method, data, params):

    try:
        return _create_asn(data)

    except PMException as e:
        logger.error(f'exception at pm.create_asn: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def peeringdb_asn_sync(method, data, params):
    asn = params.get('asn')

    if not asn:
        return False, None, 'asn parameter required'

    try:
        return _peeringdb_asn_sync(int(asn))

    except PMException as e:
        logger.error(f'exception at pm.peeringdb_asn_sync: {e.message}', exc_info=e)
        return False, e.data, e.message
