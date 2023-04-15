from copy       import deepcopy
from ipaddress  import ip_address, ip_network
import requests, json

from util.decorators import restful_method
from util.netdb      import netdb_get
from util.query      import DNS_PROJECT
from util.utildb_api import utilDB

_NETDB_COLUMN = 'interface'

_UTIL_COLLECTION = 'managed_dns'

class CloudflareException(Exception):
    """Exception raised for non-200 returns in CF API calls

    Attributes:
        url     -- CF API url
        message -- explanation of the error
    """
    def __init__(self, url, data, message):
        self.url     = url
        self.data    = data
        self.message = message
        super().__init__(self.message)


def _get_cfzones():
    filt = { "type": "managed_zone", "provider": "cloudflare" }
    result, out, comment = utilDB(_UTIL_COLLECTION).read(filt)

    if not result:
        return None

    return  {
                item['prefix'] : {
                    "account" : item['account'],
                    "zone"    : item['zone'],
                    "managed" : item['managed'],
                }

                for item in out
            }


def _get_cftoken():
    filt = { "type": "token", "provider": "cloudflare" }
    result, out, comment = utilDB(_UTIL_COLLECTION).read(filt)

    if not result:
        return None

    return out[0]['token']


def _init_cf():
    global _CF_HEADERS, _CF_MANAGED, _CF_API_PER_PAGE

    _CF_HEADERS = {
            'Content-Type'  : 'application/json',
            'Authorization' : 'Bearer ' + _get_cftoken()
        }

    _CF_MANAGED = _get_cfzones()

    _CF_API_PER_PAGE = 1000


def _get_ptrs():
    result, data, comment = netdb_get(_NETDB_COLUMN, DNS_PROJECT, project=True)

    if not result:
        return False, None, comment

    def pull_ptr(record):
        try:
            return record['meta']['dns']['ptr']
        except KeyError:
            return None

    dns  =  { 
                ip_address(k.split('/')[0]).reverse_pointer: {
                    'ptr': pull_ptr(v),
                    'ip' : k.split('/')[0],
                    }

                for i in data 
                for j in data[i]['interfaces']
                for k, v in data[i]['interfaces'][j]['address'].items()
            }
            
    return True, dns, 'netdb managed PTR records'


def _pull_cf_managed(zone):
    # Hard coded a thousand records per page. Should be enough for PTR zones.
    # may want to replace this a loop walk.
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records?per_page=%s' % (zone, _CF_API_PER_PAGE)

    resp = requests.get(url, headers = _CF_HEADERS)

    if resp.status_code != 200:
        raise CloudflareException(url, None, "_pull_cf_managed returned " + str(resp.status_code))

    return  {
                result['name'] : {
                    "ptr"     :  result['content'],
                    "ttl"     :  result['ttl'],
                    "comment" :  result['comment'],
                    "id"      :  result['id'],
                    }

                for result in resp.json()['result']
            }
            

def _cf_create(name, content, zone):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % zone

    data = {
            "name"    : name,
            "content" : content,
            "type"    : "PTR",
            "ttl"     : 1800,
            "comment" : "salt / netdb managed",
            }

    resp = requests.post(url, headers = _CF_HEADERS, data = json.dumps(data))

    if resp.status_code != 200:
        raise CloudflareException(url, data, "_cf_create returned " + str(resp.status_code))

    return resp.json()


def _cf_update(name, content, zone, cf_id):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone, cf_id)

    data = {
            "name"    : name,
            "content" : content,
            "type"    : "PTR",
            "ttl"     : 1800,
            "comment" : "salt / netdb managed",
            }

    resp = requests.put(url, headers = _CF_HEADERS, data = json.dumps(data))

    if resp.status_code != 200:
        raise CloudflareException(url, data, "_cf_update returned " + str(resp.status_code))

    return resp.json()


def _cf_delete(name, content, zone, cf_id):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone, cf_id)

    resp = requests.delete(url, headers = _CF_HEADERS)

    if resp.status_code != 200:
        raise CloudflareException(url, None, "_cf_delete returned " + str(resp.status_code))

    return resp.json()


def _gen_cf_managed(ptrs):
    cf_managed = deepcopy(_CF_MANAGED)

    out = {}
    for name, meta  in ptrs.items():
        ip   = meta['ip']
        ptr  = meta['ptr']
        addr = ip_address(ip)
        cidr = str(addr.max_prefixlen)

        for k, v in cf_managed.items():
            # Load list of existing CF records if not already done
            if 'cfptrs' not in v:
                v['cfptrs'] = _pull_cf_managed(_CF_MANAGED[k]['zone'])

                for ck, cv in v['cfptrs'].items():
                    # If a CF record does not exist in netdb then delete it
                    if _CF_MANAGED[k]['managed'] and ck not in ptrs.keys():
                        out.update({ ck : {
                                "ptr"       :  cv['ptr'], 
                                "cf_id"     :  cv['id'],
                                "action"    :  "delete",
                                "account"   :  _CF_MANAGED[k]['account'],
                                "zone"      :  _CF_MANAGED[k]['zone'],
                                }
                            })

            try:
                if ip_network(ip + '/' + cidr).subnet_of(ip_network(k)):
                    # new record in CF
                    if name not in v['cfptrs']:
                        action = 'create'
                        cf_id = None
                        update = True

                    # record exists but content has changed
                    elif ptr != v['cfptrs'][name]['ptr']:
                        action = 'update'
                        cf_id = v['cfptrs'][name]['id']
                        update = True

                    # record exists and up-to-date. no action needed
                    else:
                        update = False

                    # add the ptr to the list of managed records w/ required action
                    if update and ptr:
                        out.update({ name : {
                            "ptr"      :  ptr, 
                            "action"   :  action,
                            "cf_id"    :  cf_id,
                            "account"  :  _CF_MANAGED[k]['account'],
                            "zone"     :  _CF_MANAGED[k]['zone'],
                            }
                        })

                    # PTR only in one zone. No need to continue iterating
                    break

            except TypeError:
                pass

    return out


def _update_cf_records(cf_managed):
    for name, content in cf_managed.items():
        if content['action'] == 'create':
            _cf_create(name, content['ptr'], content['zone'])

        elif content['action'] == 'update':
            _cf_update(name, content['ptr'], content['zone'], content['cf_id'])

        elif content['action'] == 'delete':
            _cf_delete(name, content['ptr'], content['zone'], content['cf_id'])


@restful_method(methods = ['GET', 'POST'])
def set_cfzone(method, data):
    entry = {
            'type'     :  'managed_zone',
            'provider' :  'cloudflare',
            'zone'     :  data.get('zone'),
            'account'  :  data.get('account'),
            'managed'  :  data.get('managed'),
            'prefix'   :  data.get('prefix'),
            }

    if not all(isinstance(i, str) for i in [ entry['zone'], entry['account'], entry['prefix'] ]):
        return False, None, 'zone, account and prefix must be set'

    if not isinstance(entry['managed'], bool):
        return False, None, 'managed must be either true or false'

    try:
        ip_network(entry['prefix'])
    except ValueError:
        return False, None, 'invalid prefix'

    if method == 'POST':
        filt = { "prefix": entry['prefix'], "type": "managed_zone", "provider": "cloudflare" }

        result, out, comment = utilDB(_UTIL_COLLECTION).replace_one(filt, entry)
        return result, entry, comment
    else:
        return True, entry, 'dry run: database not updated'


@restful_method(methods = ['DELETE'])
def delete_cfzone(method, data):
    prefix = data.get('prefix')

    try:
        ip_network(prefix)
    except ValueError:
        return False, None, 'invalid prefix'

    db = utilDB(_UTIL_COLLECTION)
    filt = { "prefix": prefix, "type": "managed_zone", "provider": "cloudflare" }

    return db.delete(filt)


@restful_method
def get_cfzones(method, data):
    result = _get_cfzones()

    if result:
        return True, result, 'cf managed zones'
    else:
        return False, None, 'no cf managed zones found'


@restful_method(methods = ['POST'])
def set_cftoken(method, data):
    token = data.get('token')
    if not isinstance(token, str):
        return False, None, 'token must be a valid string'

    entry = {
            "type"     : "token",
            "provider" : "cloudflare",
            "token"    : token,
            }

    db = utilDB(_UTIL_COLLECTION)
    filt = { "type": "token", "provider": "cloudflare" }

    return db.replace_one(filt, entry)


@restful_method
def get_ptrs(method, data):
    """
    Get a list of all PTRs registered in netdb 

    :param None: No parameters for this method.
    """
    return _get_ptrs()


@restful_method
def get_cf(method, data):
    _init_cf()

    cf_managed = deepcopy(_CF_MANAGED)

    try:
        for zone, zone_data in cf_managed.items():
            zone_data['ptrs'] = _pull_cf_managed(_CF_MANAGED[zone]['zone'])

    except CloudflareException as e:
        return False, { 'url': e.url }, e.message

    return True, cf_managed, 'CF managed PTR Zones'


@restful_method(methods = ['GET', 'POST'])
def update_cf(method, data):
    _init_cf()

    result, data, comment = _get_ptrs()

    if not result:
        return result, data, comment

    success = True
    try:
        cf_managed = _gen_cf_managed(data)
        if not cf_managed:
            success = False
            comment = 'All netdb managed zones and records up to date.'

        elif method == 'POST':
            _update_cf_records(cf_managed)
            comment = 'Update of netdb managed zones and records complete'
        else:
            comment = 'List of netdb records requiring synchronisation'

    except CloudflareException as e:
        success    = False
        cf_managed = { 'url': e.url, 'data': e.data }
        comment    = e.message

    return success, cf_managed, comment
