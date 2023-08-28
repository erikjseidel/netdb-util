import requests, json, logging, yaml, ipaddress
from marshmallow import ValidationError
from copy import deepcopy
from config import pm
from schema import pm as pm_schema
from util import netdb
from util.django_api import DjangoAPI
from util.web_api import WebAPIException

_DATASOURCE = pm.PM_SOURCE['name']
_BGP_COLUMN = 'bgp'

NETDB_CONTAINER = {
        'datasource' : _DATASOURCE,
        'weight'     : pm.PM_SOURCE['weight'],
        }

logger = logging.getLogger(__name__)

def _container(data):
    return {
            'column' : data,
            **NETDB_CONTAINER
            }


class PeeringManagerAPI(DjangoAPI):
    """
    Simple class for interacting with Peering Manager API.
    """
    _API_BASE = pm.PM_URL + '/api'

    _PUBLIC_API_BASE = pm.PM_PUBLIC_URL + '/api'

    _HEADERS = pm.PM_HEADERS

    # Used for exception error messages
    _ERR_MSG = 'PM API returned an error'

    ENDPOINTS = {
        'direct-sessions' : 'peering/direct-peering-sessions',
        'ixp-sessions'    : 'peering/internet-exchange-peering-sessions',
        'policies'        : 'peering/routing-policies',
        'groups'          : 'peering/bgp-groups',
        'asns'            : 'peering/autonomous-systems',
        'ixps'            : 'peering/internet-exchanges',
        'routers'         : 'peering/routers',
        'connections'     : 'net/connections',
        'relationships'   : 'bgp/relationships',
        }


class PMException(WebAPIException):
    pass


class PeeringManagerUtility:

    def __init__(self, test=False):

        # Maps relationship vars to search methods. Used to
        # resolve names to ids for each relationship
        self.SEARCH_METHODS = {
                'local_asn' : self.search_asns,
                'peer_asn'  : self.search_asns,
                'type'      : self.search_relationships,
                'import'    : self.search_policies,
                'export'    : self.search_policies,
                'device'    : self.search_routers,
                }

        self.test = test
        self.pm_api = PeeringManagerAPI()


    def _resolve_relationships(self, data):
        out = {}

        # Populate the child relationships
        for k, v in pm_schema.DIRECT_SESSION_VARS.items():
            child = data.pop(k, None)

            # Zero means empty
            if child == 0:
                out[v] = 0

            elif child:
                if id := self.SEARCH_METHODS[k](child):
                    out[v] = id
                else:
                    raise PMException(message=f'{k} {child} not found in PM')

        return out


    def search_direct_sessions(self, device, ip):
        try:
            ipaddress.ip_address(ip)
        except:
            return None

        sessions = self.pm_api.set('direct-sessions').set_params(q=ip).get()

        for session in sessions:
            if ( session['router'].get('name') == device 
                    and session.get('ip_address').split('/')[0] == ip ):
                return session.get('id')

        return None


    def search_ixp_sessions(self, device, ip):
        try:
            ipaddress.ip_address(ip)
        except:
            return None

        sessions = self.pm_api.set('ixp-sessions').set_params(q=ip).get()
        connections = { i.pop('id') : i for i in self.pm_api.set('connections').get() }

        for session in sessions:
            connection_id = session['ixp_connection'].get('id')
            if ( connections[connection_id]['router'].get('name') == device
                    and session.get('ip_address') == ip ):
                return session.get('id')

        return None


    def search_policies(self, name):
        policies = self.pm_api.set('policies').set_params(q=name).get()

        for policy in policies:
            if policy.get('name') == name:
                return policy.get('id')

        return None


    def search_asns(self, number):
        asns = self.pm_api.set('asns').set_params(q=number).get()

        for asn in asns:
            if asn.get('asn') == number:
                return asn.get('id')

        return None


    def search_relationships(self, slug):
        relationships = self.pm_api.set('relationships').set_params(q=slug).get()

        for relationship in relationships:
            if relationship.get('slug') == slug:
                return relationship.get('id')

        return None


    def search_routers(self, name):
        routers = self.pm_api.set('routers').set_params(name=name).get()

        for router in routers:
            if router.get('name') == name:
                return router.get('id')

        return None


    def create_policy(self, data):
        data_in = { k: v for k, v in data.items() if v }

        try:
            policy = pm_schema.PolicySchema().load(data_in)
        except ValidationError as error:
            return False, error.messages, 'invalid policy data'

        ret = self.pm_api.set('policies').post(policy)

        return True, ret, 'Policy created'


    def delete_policy(self, name):
        id = self.search_policies(name)
        if not id:
            return False, None, 'Policy not found in Peering Manager'

        self.pm_api.set('policies').set_id(id).delete()

        return True, None, 'Policy deleted'


    def generate_policies(self, pm_object, policies, family):
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


    def create_asn(self, data):
        data_in = { k: v for k, v in data.items() if v }

        try:
            asn = pm_schema.AsnSchema().load(data_in)
        except ValidationError as error:
            return False, error.messages, 'invalid ASN data'

        ret = self.pm_api.set('asns').post(asn)

        return True, ret, 'ASN created'


    def peeringdb_asn_sync(self, name):

        id = self.search_asns(name)
        if not id:
            return False, None, 'ASN not found in Peering Manager'

        self.pm_api.set('asns').set_id(id).set_suffix('sync-with-peeringdb').post()

        return True, None, 'ASN synchronized from peeringdb'
        

    def delete_asn(self, name):

        id = self.search_asns(name)
        if not id:
            return False, None, 'ASN not found in Peering Manager'

        self.pm_api.set('asns').set_id(id).delete()

        return True, None, 'ASN deleted'


    def create_direct_session(self, data):

        # Check that all incoming keys are valid options.
        for k in data.keys():
            if k not in pm_schema.ADD_DIRECT_SESSION_MASK:
                return False, None, f'{k}: invalid key'

        # PM will allow addition of multiple sessions with the same device
        # and remote IP. Prevent this from happening via netb-util calls.
        device = data.get('device')
        remote_ip = data.get('remote_ip')
        if self.search_direct_sessions(device, remote_ip):
            return False, None, f'{remote_ip} at {device}: session already exists'

        if status := data.get('status'):
            if status not in pm_schema.PM_STATUS:
                return False, None, 'Invalid session status'

        data_in = self._resolve_relationships(data)

        # Update data_in with remaining input data
        data_in.update({ k: v for k, v in data.items() if v })

        try:
            session = pm_schema.DirectSessionSchema().load(data_in)
        except ValidationError as error:
            return False, error.messages, 'invalid session data'

        ret = self.pm_api.set('direct-sessions').post(session)

        out = self.reload_session(device, remote_ip)

        return True, out, 'Direct session created in Peering Manager'


    def update_direct_session(self, data):

        # Check that all incoming keys are valid options.
        for k in data.keys():
            if k not in pm_schema.UPDATE_DIRECT_SESSION_MASK:
                return False, None, f'{k}: invalid key'

        device = data.pop('device', None)
        remote_ip = data.pop('remote_ip', None)
        if not ( id := self.search_direct_sessions(device, remote_ip) ):
            return False, None, f'{remote_ip} at {device}: session not found'

        data_in = self._resolve_relationships(data)

        # Update data_in with remaining input data
        data_in.update({ k: v for k, v in data.items() if v })

        try:
            session = pm_schema.DirectSessionSchema().load(data_in)
        except ValidationError as error:
            return False, error.messages, 'invalid session data'

        ret = self.pm_api.set('direct-sessions').set_id(id).patch(session)

        out = self.reload_session(device, remote_ip)

        return True, out, 'Direct session updated in Peering Manager'


    def delete_direct_session(self, device, ip):

        if not ( id := self.search_direct_sessions(device, ip) ):
            return False, None, 'Direct session not found in Peering Manager'

        self.pm_api.set('direct-sessions').set_id(id).delete()

        filt = [device, 'neighbors', ip]

        netdb.delete(_BGP_COLUMN, filt)

        return result, None, 'Direct session deleted in Peering Manager'


    def generate_direct_session_base(self, session):
        if ( status := session['status'].get('value') ) == 'disabled':
            return None

        # Turn these into `id' keyed dicts for quick lookups. 
        groups   = { i.pop('id') : i for i in self.pm_api.set('groups').get() }
        asns     = { i.pop('id') : i for i in self.pm_api.set('asns').get() }
        policies = { i.pop('id') : i for i in self.pm_api.set('policies').get() }

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

        source_ip = session.get('local_ip_address')

        entry = {
                'remote_asn' : session['autonomous_system'].get('asn'),
                'multihop'   : session.get('multihop_ttl'),
                'password'   : session.get('password'),
                'source'     : source_ip.split('/')[0] if source_ip else None,
                'type'       : 'ebgp',
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

        asn_policies = self.generate_policies(asn, policies, family)

        for i in ['import_routing_policies', 'export_routing_policies']:
            if 'reject' in tags or status == 'maintenance':
                route_map[ i.split('_')[0] ] = pm_schema.DEFAULT_REJECT
            elif len(session[i]) > 0:
                route_map[ i.split('_')[0] ] = session[i][0]['name']
            elif group and len(group[i]) > 0:
                route_map[ i.split('_')[0] ] = group[i][0]['name']
            elif asn_policies and len(asn_policies[i]) > 0:
                # If no session or group policies, we can try ASN
                route_map[ i.split('_')[0] ] = asn_policies[i][0]
            else:
                route_map[ i.split('_')[0] ] = pm_schema.DEFAULT_REJECT

        addr_fam['route_map'] = route_map

        relationship = session['relationship'].get('slug')

        if relationship != 'transit-session':
            if family == 6:
                max_prefixes = session['autonomous_system'].get('ipv6_max_prefixes')
            else:
                max_prefixes = session['autonomous_system'].get('ipv4_max_prefixes')

            if max_prefixes:
                addr_fam['max_prefixes'] = max_prefixes

        url = PeeringManagerAPI('direct-sessions').set_id(session_id).get_public_url()

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


    def generate_ixp_session_base(self, session):
        if ( status := session['status']['value'] ) == 'disabled':
            return None

        # Turn these into `id' keyed dicts for quick lookups. 
        connections = { i.pop('id') : i for i in self.pm_api.set('connections').get() }
        ixps        = { i.pop('id') : i for i in self.pm_api.set('ixps').get() }
        asns        = { i.pop('id') : i for i in self.pm_api.set('asns').get() }
        policies    = { i.pop('id') : i for i in self.pm_api.set('policies').get() }

        session_id = int(session['id'])

        connection_id = session['ixp_connection']['id']
        connection = connections.get(connection_id)

        ixp_id = connection['internet_exchange_point']['id']
        ixp = ixps.get(ixp_id)

        if 'disabled' in [ connection['status']['value'], ixp['status']['value'] ]:
            return None

        if 'maintenance' in [ session['status']['value'], connection['status']['value'], ixp['status']['value'] ]:
            status = 'maintenance'

        tags = [ i['name'] for i in (session['tags'] + connection['tags'] + ixp['tags']) ]

        device = connection['router'].get('name')
        ip = session.get('ip_address').split('/')[0]

        if ipaddress.ip_address(ip).version == 6:
            family = 6
        else:
            family = 4

        entry = {
                'remote_asn' : session['autonomous_system'].get('asn'),
                'password'   : session.get('password'),
                'type'       : 'ebgp',
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
        ixp_asn_policies = self.generate_policies(asn, policies, family)
        if not ixp_asn_policies:
            # No ASN policies found. Next try IXP.
            ixp_asn_policies = self.generate_policies(ixp, policies, family)

        # Add policies to BGP entry
        for i in ['import_routing_policies', 'export_routing_policies']:
            if 'reject' in tags or status == 'maintenance':
                route_map[ i.split('_')[0] ] = pm_schema.DEFAULT_REJECT
            elif len(session[i]) > 0:
                # Session policies have highest priority
                route_map[ i.split('_')[0] ] = session[i][0]['name']
            elif ixp_asn_policies and len(ixp_asn_policies[i]) > 0:
                # If no session policies, we can try ASN or IXP
                route_map[ i.split('_')[0] ] = ixp_asn_policies[i][0]
            else:
                route_map[ i.split('_')[0] ] = pm_schema.DEFAULT_REJECT

        addr_fam['route_map'] = route_map

        if 'ix_transit' not in tags:
            if family == 6:
                max_prefixes = session['autonomous_system'].get('ipv6_max_prefixes')
            else:
                max_prefixes = session['autonomous_system'].get('ipv4_max_prefixes')

            if max_prefixes:
                addr_fam['max_prefixes'] = max_prefixes

        url = PeeringManagerAPI('ixp-sessions').set_id(session_id).get_public_url()

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


    def generate_direct_sessions(self):
        sessions = self.pm_api.set('direct-sessions').get()

        out = {}

        if sessions:
            for session in sessions:
                result = self.generate_direct_session_base(session)
                if not result:
                    continue

                if not out.get(result['device']):
                    out[ result['device'] ] = { 'neighbors' : {} }
                out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']
        else:
            return None

        return out


    def generate_direct_session(self, id):
        session = self.pm_api.set('direct-sessions').set_id(id).get()

        out = {}

        if session.get('id'):
            result = self.generate_direct_session_base(session)
            if not result:
                return None

            out[ result['device'] ] = { 'neighbors' : {} }
            out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']
        else:
            return None

        return out


    def generate_ixp_sessions(self):
        sessions = self.pm_api.set('ixp-sessions').get()

        out = {}

        if sessions:
            for session in sessions:
                result = self.generate_ixp_session_base(session)
                if not result:
                    continue

                if not out.get(result['device']):
                    out[ result['device'] ] = { 'neighbors' : {} }
                out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']
        else:
            return None

        return out


    def generate_ixp_session(self, id):
        session = self.pm_api.set('ixp-sessions').set_id(id).get()

        out = {}

        if session.get('id'):
            result = self.generate_ixp_session_base(session)
            if not result:
                return None

            out[ result['device'] ] = { 'neighbors' : {} }
            out[ result['device'] ]['neighbors'][ result['ip'] ] = result['data']
        else:
            return None

        return out


    def generate_session(self, device, ip):
        out = None

        # Try direct sessions first
        if session_id := self.search_direct_sessions(device, ip):
            out = self.generate_direct_session(session_id)

        # No direct sessions found; try IXP session
        elif session_id := self.search_ixp_sessions(device, ip):
            out = self.generate_ixp_session(session_id)

        # No sessions found
        return out


    def generate_ebgp(self):
        pm_sessions = self.generate_ixp_sessions()
     
        # Pull direct sessions and merge them on top of IXP sessions.
        for device, neighbors in self.generate_direct_sessions().items():
            if not pm_sessions.get(device):
                pm_sessions[device] = { 'neighbors' : {} }
            for neighbor, bgp_data in neighbors.get('neighbors').items():
                pm_sessions[device]['neighbors'][neighbor] = bgp_data

        return pm_sessions


    def reload_session(self, device, ip):
        if not (pm_session := self.generate_session(device, ip)):
            raise PMException(message=f'Neighbor not found!')

        return netdb.replace(_BGP_COLUMN, _container(pm_session))


    def reload_ebgp(self):
        data = self.generate_ebgp()

        return netdb.reload(_BGP_COLUMN, _container(data))


    def set_status(self, device, ip, status):
        if status not in pm_schema.PM_STATUS:
            return False, None, 'invalid session status'

        data = { 'status': status }

        # Try direct sessions first
        if session_id := self.search_direct_sessions(device, ip):
            self.pm_api.set('direct-sessions').set_id(session_id)

        # No direct sessions found; try IXP session
        elif session_id := self.search_ixp_sessions(device, ip):
            self.pm_api.set('ixp-sessions').set_id(session_id)

        # No sessions found.
        else:
            return False, None, 'PM eBGP session not found.'

        session = self.pm_api.get()
        if session['status'].get('value') == status:
            return False, None, 'Status not changed'

        self.pm_api.patch(data)

        # Reload netdb entry and return
        return True, self.reload_session(device, ip), 'Status updated.'
