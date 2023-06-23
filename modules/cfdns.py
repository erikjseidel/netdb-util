from copy import deepcopy
from ipaddress import ip_address, ip_network
from util import netdb
from util.query import DNS_PROJECT
from util.utildb_api import utilDB
from config.secrets import CFDNS_TOKEN

import requests, json

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


def get_cfzones():
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


def init_cf():
    global _CF_HEADERS, _CF_MANAGED, _CF_API_PER_PAGE

    _CF_HEADERS = {
            'Content-Type'  : 'application/json',
            'Authorization' : 'Bearer ' + CFDNS_TOKEN
        }

    _CF_MANAGED = get_cfzones()

    _CF_API_PER_PAGE = 1000

    return deepcopy(_CF_MANAGED)


def get_ptrs():
    result, data, comment = netdb.get(_NETDB_COLUMN, DNS_PROJECT, project=True)

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
                for j in data[i]
                for k, v in data[i][j]['address'].items()
            }
            
    return True, dns, 'netdb managed PTR records'


def pull_cf_managed(zone):
    # Hard coded a thousand records per page. Should be enough for PTR zones.
    # may want to replace this a loop walk.
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records?per_page=%s' % (zone, _CF_API_PER_PAGE)

    resp = requests.get(url, headers = _CF_HEADERS)

    if resp.status_code != 200:
        raise CloudflareException(url, None, "pull_cf_managed returned " + str(resp.status_code))

    return  {
                result['name'] : {
                    "ptr"     :  result['content'],
                    "ttl"     :  result['ttl'],
                    "comment" :  result['comment'],
                    "id"      :  result['id'],
                    }

                for result in resp.json()['result']
            }
            

def cf_create(name, content, zone):
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
        raise CloudflareException(url, data, "cf_create returned " + str(resp.status_code))

    return resp.json()


def cf_update(name, content, zone, cf_id):
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


def cf_delete(name, content, zone, cf_id):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone, cf_id)

    resp = requests.delete(url, headers = _CF_HEADERS)

    if resp.status_code != 200:
        raise CloudflareException(url, None, "cf_delete returned " + str(resp.status_code))

    return resp.json()


def gen_cf_managed(ptrs):
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
                v['cfptrs'] = pull_cf_managed(_CF_MANAGED[k]['zone'])

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


def update_cf_records(cf_managed):
    for name, content in cf_managed.items():
        if content['action'] == 'create':
            cf_create(name, content['ptr'], content['zone'])

        elif content['action'] == 'update':
            cf_update(name, content['ptr'], content['zone'], content['cf_id'])

        elif content['action'] == 'delete':
            cf_delete(name, content['ptr'], content['zone'], content['cf_id'])
