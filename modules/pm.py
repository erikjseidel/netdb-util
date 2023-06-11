import requests, json, logging, time, yaml, ipaddress
from copy import deepcopy
from util.decorators import restful_method
from config import pm
from util.netdb import (
        NetdbException, netdb_get, netdb_validate, 
        netdb_add, netdb_replace, netdb_delete
        )

# Public symbols
__all__ = [
        'synchronize_direct_sessions',
        'generate_direct_sessions',
        ]

_NETDB_BGP_COLUMN   = 'bgp'

_FILTER = { 'datasource': pm.PM_SOURCE['name'] }

_DEFAULT_REJECT = 'REJECT-ALL'

logger = logging.getLogger(__name__)

class PeeringManager:
    _BASE = pm.PM_BASE
    _HEADERS = pm.PM_HEADERS
    
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

        logger.debug(f'PM.get: {url}')
        resp = requests.get(url, headers = self._HEADERS)
        
        if (code := resp.status_code) != 200:
            raise PMException(url, resp.json(), code)

        if 'results' in ( json := resp.json() ):
            return json['results']
        return json


    def post(self, data):
        url = self.url
        logger.debug(f'PM.get: {url}')
        resp = requests.post(url, headers = self._HEADERS, json = data )

        if 'results' in ( js := resp.json() ):
            return js['results']

        return js['result'] if 'result' in js else js


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


def _generate_direct_sessions():
    sessions = PeeringManager('peering/direct-peering-sessions').get()

    out = {}
    if sessions:
        for session in sessions:
            if session['status'].get('value') != 'enabled':
                continue

            tags = [ i['name'] for i in session['tags'] ]

            device = session['router'].get('name')
            ip = session.get('ip_address').split('/')[0]

            if ipaddress.ip_address(ip).version == 6:
                family = 'ipv6'
            else:
                family = 'ipv4'

            url = f"{pm.PM_URL_BASE}/direct-peering-sessions/{session['id']}/"

            entry = {
                    'remote_asn' : session['autonomous_system'].get('asn'),
                    'multihop'   : session.get('multihop_ttl'),
                    'password'   : session.get('password'),
                    'source'     : session.get('local_ip_address').split('/')[0],
                    'type'       : 'ebgp',
                    'datasource' : pm.PM_SOURCE['name'],
                    'weight'     : pm.PM_SOURCE['weight'],
                    }

            addr_fam  = { 'nhs' : 'y'}
            route_map = {}
            for i in ['import_routing_policies', 'export_routing_policies']:
                if len(session[i]) > 0 and 'reject' not in tags:
                    route_map[ i.split('_')[0] ] = session[i][0]['name']
                else:
                    route_map[ i.split('_')[0] ] = _DEFAULT_REJECT

            addr_fam['route_map'] = route_map

            meta = {
                    'id'           : int(session['id']),
                    'url'          : url,
                    'status'       : session['status'].get('value'),
                    'tags'         : tags,
                    'comments'     : session.get('comments'),
                    }
            meta = { k : v for k, v in meta.items() if v }

            entry.update({
                'meta'   : { 'peering_manager' : meta },
                'family' : { family : addr_fam },
                })

            if not out.get(device):
                out[device] = { 'neighbors' : {} }
            out[device]['neighbors'][ip] = { k : v for k, v in entry.items() if v }

    return out


def _synchronize_direct_sessions(test=True):
    # Load and validation
    pm_sessions = _generate_direct_sessions()

    result, out, message = netdb_validate(_NETDB_BGP_COLUMN, data = pm_sessions)
    if not result:
        return result, out, message

    result, netdb_ebgp, _ = netdb_get(_NETDB_BGP_COLUMN, data = _FILTER)
    if not result:
        netdb_ebgp = {}

    all_changes = {}
    adjective = 'required' if test else 'complete'

    # Apply to netdb
    for device, ebgp_data in pm_sessions.items():
        changes  = {}
        for neighbor, data in ebgp_data['neighbors'].items():
            if netdb_ebgp.get(device) and neighbor in netdb_ebgp[device]['neighbors'].keys():
                if data != netdb_ebgp[device]['neighbors'][neighbor]:
                    # Update required.
                    if not test:
                        netdb_replace(_NETDB_BGP_COLUMN, data = { device: { 'neighbors' : { neighbor: data }}})
                    changes[neighbor] = {
                            '_comment': f'update {adjective}',
                            **data
                            }
                netdb_ebgp[device]['neighbors'].pop(neighbor)
            else:
                # Addition required
                if not test:
                    netdb_add(_NETDB_BGP_COLUMN, data = { device: { 'neighbors' : { neighbor: data }}})
                changes[neighbor] = {
                        '_comment': f'addition {adjective}',
                        **data
                        }

        # Any remaining (unpopped) interfaces in netdb need to be deleted
        if netdb_ebgp.get(device):
            for neighbor in netdb_ebgp[device]['neighbors'].keys():
                # Deletion required
                if not test:
                    filt = { "set_id": [device, 'neighbors', neighbor], **_FILTER }
                    netdb_delete(_NETDB_BGP_COLUMN, data = filt)
                changes[neighbor] = {
                       '_comment': f'removal from netdb {adjective}',
                       }

        if changes:
            all_changes[device] = {}
            all_changes[device]['neighbors'] = changes

    if not all_changes:
        message = 'Netdb eBGP sessions already synchronized. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    if not test:
        logger.info(f'_synchronize_ebgp: {message}')

    return True if all_changes else False, all_changes, message


@restful_method
def generate_direct_sessions(method, data, params):
    try:
        data = _generate_direct_sessions()

    except PMException as e:
        logger.error(f'exception at pm.generate_direct_sessions: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'eBGP direct sessions generated from Peering Manager datasource'


@restful_method
def synchronize_direct_sessions(method, data, params):
    test = True
    if params.get('test') in ['false', 'False']:
        test = False

    try:
        return _synchronize_direct_sessions(test)
    except PMException as e:
        return False, e.data, e.message
