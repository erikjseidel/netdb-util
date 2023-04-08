from copy       import deepcopy
from ipaddress  import ip_address, ip_network
import requests, json

from util.decorators import restful_method
from util.netdb      import netdb_get
from util.query      import DNS_PROJECT
from util.private    import CF_TOKEN, CF_ZONES

_NETDB_COLUMN = 'interface'

_CF_MANAGED = {
        "23.181.64.0/24": CF_ZONES['64.181.23.in-addr.arpa'],
        }

_CF_HEADERS = {
        'Content-Type'  : 'application/json',
        'Authorization' : 'Bearer ' + CF_TOKEN,
        }

def _get_ptrs():
    result, data, comment = netdb_get(_NETDB_COLUMN, DNS_PROJECT, project=True)

    if not result:
        return False, None, comment

    dns =   { 
                k[0].split('/')[0]:
                    k[1]['meta']['dns']['ptr'] if 'ptr' in k[1]['meta']['dns'] else None 
                for i in data 
                for j in data[i]['interfaces']
                for k in data[i]['interfaces'][j]['address'].items()
            }
            
    return True, dns, 'netdb managed PTR records'


def _pull_cf_managed(zone):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % zone['zone']

    resp = requests.get(url, headers = _CF_HEADERS).json()

    cflare = {}
    for result in resp['result']: 
        cflare.update({ result['name'] : {
            "ptr" :  result['content'],
            "id"  :  result['id'],
            }
        })
            
    return cflare


def _cf_create(name, content, zone):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % zone

    data = {
            "name"    : name,
            "content" : content,
            "type"    : "PTR",
            "ttl"     : 1800,
            "comment" : "salt / netdb managed",
            }

    resp = requests.post(url, headers = _CF_HEADERS, data = json.dumps(data)).json()

    return resp['success'], resp, "cloudflare answer"


def _cf_update(name, content, zone, cf_id):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone, cf_id)

    data = {
            "name"    : name,
            "content" : content,
            "type"    : "PTR",
            "ttl"     : 1800,
            "comment" : "salt / netdb managed",
            }

    resp = requests.put(url, headers = _CF_HEADERS, data = json.dumps(data)).json()

    return resp['success'], resp, "cloudflare answer"


def _cf_delete(name, content, zone, cf_id):
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone, cf_id)

    resp = requests.delete(url, headers = _CF_HEADERS)

    if resp.status_code == 200:
        result = True
    else:
        result = False

    return result, resp.json(), "cloudflare answer"


def _gen_cf_managed(ptrs):
    cf_managed = deepcopy(_CF_MANAGED)

    out = {}
    
    for ip, ptr in ptrs.items():
        addr = ip_address(ip)
        cidr = str(addr.max_prefixlen)
        name = addr.reverse_pointer

        for k, v in cf_managed.items():
            if 'ptrs' not in v:
                v['ptrs'] = {}

            # Load list of existing CFLARE records if not already done
            if 'cfptrs' not in v:
                v['cfptrs'] = _pull_cf_managed(_CF_MANAGED[k])
                for ck, cv in v['cfptrs'].items():

                    # If a CF record does not exist in netdb then delete it
                    if ck not in ptrs:
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

                    # record exists but content has changed
                    elif ptr != v['cfptrs'][name]['ptr']:
                        action = 'update'
                        cf_id = v['cfptrs'][name]['id']

                    # record exists and up-to-date. no action needed.
                    else:
                        action = 'pass'
                        cf_id = v['cfptrs'][name]['id']
                    out.update({ name : {
                            "ptr"      :  ptr, 
                            "action"   :  action,
                            "cf_id"   :  cf_id,
                            "account"  :  _CF_MANAGED[k]['account'],
                            "zone"     :  _CF_MANAGED[k]['zone'],
                            }
                        })
                    break
            except TypeError:
                pass

    return out


def _update_cf_records(cf_managed):
    for name, content in cf_managed.items():
        if content['action'] == 'create':
            result, out, comment = _cf_create(name, content['ptr'], content['zone'])

        elif content['action'] == 'update':
            result, out, comment = _cf_update(name, content['ptr'], content['zone'], content['cf_id'])

        elif content['action'] == 'delete':
            result, out, comment = _cf_delete(name, content['ptr'], content['zone'], content['cf_id'])

        elif content['action'] == 'pass':
            result  = True 
            out     = None 
            comment = 'no action'

        # We should never reach this point
        else:
            result  = False 
            out     = None
            comment = 'invalid dns record action'

        if not result:
            return result, out, comment

    return True, None, 'CF update complete'


@restful_method
def get_ptrs(method, data):
    """
    Get a list of all PTRs registered in netdb 

    :param None: No parameters for this method.
    """
    return _get_ptrs()


@restful_method
def get_cf(method, data):
    return True, _CF_MANAGED, 'CF managed PTR Zones'


@restful_method(methods = ['GET', 'POST'])
def update_cf(method, data):
    result, data, comment = _get_ptrs()

    if not result:
        return result, data, comment

    cf_managed = _gen_cf_managed(data)

    if method == 'POST':
        result, out, comment = _update_cf_records(cf_managed)
        return result, cf_managed, comment
    else:
        return True, cf_managed, 'Dry Run: CF update list'
