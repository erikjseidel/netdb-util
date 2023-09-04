import requests, json

from copy import deepcopy
from ipaddress import ip_address, ip_network
from util import netdb
from util.query import DNS_PROJECT
from util.utildb_api import utilDB
from config.secrets import CFDNS_TOKEN
from util.exception import UtilityAPIException

_NETDB_COLUMN = 'interface'

_UTIL_COLLECTION = 'managed_dns'

CF_API_URL = 'https://api.cloudflare.com/client/v4/zones/{zone}/dns_records'
CF_API_ID_URL = 'https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{id}'

class CloudflareException(UtilityAPIException):
    pass


class CloudflareDNSConnector:

    # Hardcoded for now; may want to replace this a loop walk.
    CF_API_PER_PAGE = 1000

    CF_HEADERS = {
            'Content-Type'  : 'application/json',
            'Authorization' : 'Bearer ' + CFDNS_TOKEN
        }


    def __init__(self):
        self.CF_MANAGED = self.get_cfzones()


    def _get_ptrs(self):
        data = netdb.get(_NETDB_COLUMN)['out']

       # raise CloudflareException(data=data)

        def pull_ptr(record):
            try:
                return record['meta']['dns']['ptr']
            except KeyError:
                return None

        dns = {
                ip_address(k.split('/')[0]).reverse_pointer: {
                    'ptr': pull_ptr(v),
                    'ip' : k.split('/')[0],
                    }

                for i in data 
                for j in data[i]
                if data[i][j].get('address')
                for k, v in data[i][j]['address'].items()
                }
            
        return dns


    def _create_record(self, name, content, zone):
        url = CF_API_URL.format(zone=zone)

        data = {
                "name"    : name,
                "content" : content,
                "type"    : "PTR",
                "ttl"     : 1800,
                "comment" : "salt / netdb managed",
                }

        resp = requests.post(url, headers=self.CF_HEADERS, data=json.dumps(data))

        if resp.status_code != 200:
            raise CloudflareException(
                    url=url,
                    code=400,
                    data=data,
                    message="cf_create returned {}".format(resp.status_code),
                    )

        return resp.json()


    def _update_record(self, name, content, zone, cf_id):
        url = CF_API_ID_URL.format(zone=zone, id=cf_id)

        data = {
                "name"    : name,
                "content" : content,
                "type"    : "PTR",
                "ttl"     : 1800,
                "comment" : "salt / netdb managed",
                }

        resp = requests.put(url, headers=self.CF_HEADERS, data=json.dumps(data))

        if resp.status_code != 200:
            raise CloudflareException(
                    url=url,
                    code=400,
                    data=data,
                    message="cf_update returned {}".format(resp.status_code),
                    )

        return resp.json()


    def _delete_record(self, name, content, zone, cf_id):
        url = CF_API_ID_URL.format(zone=zone, id=cf_id)

        resp = requests.delete(url, headers=self.CF_HEADERS)

        if resp.status_code != 200:
            raise CloudflareException(
                    url=url,
                    code=400,
                    message="cf_delete returned {}".format(resp.status_code),
                    )

        return resp.json()


    def _pull_cf_managed(self, zone):
        url = CF_API_URL.format(zone=zone)
        params = {'per_page' : self.CF_API_PER_PAGE}

        resp = requests.get(url, params=params, headers=self.CF_HEADERS)

        if resp.status_code != 200:
            raise CloudflareException(
                    url=url,
                    code=400,
                    message="pull_cf_managed returned {}".format(resp.status_code),
                    )

        return {
                    result['name'] : {
                        "ptr"     :  result['content'],
                        "ttl"     :  result['ttl'],
                        "comment" :  result['comment'],
                        "id"      :  result['id'],
                        }

                    for result in resp.json()['result']
                }


    def _gen_cf_managed(self, ptrs):
        cf_managed = deepcopy(self.CF_MANAGED)

        out = {}
        for name, meta  in ptrs.items():
            ip   = meta['ip']
            ptr  = meta['ptr']
            addr = ip_address(ip)
            cidr = str(addr.max_prefixlen)

            for k, v in cf_managed.items():
                # Load list of existing CF records if not already done
                if 'cfptrs' not in v:
                    v['cfptrs'] = self._pull_cf_managed(self.CF_MANAGED[k]['zone'])

                    for ck, cv in v['cfptrs'].items():
                        # If a CF record does not exist in netdb then delete it
                        if self.CF_MANAGED[k]['managed'] and ck not in ptrs.keys():
                            out.update({ ck : {
                                    "ptr"       :  cv['ptr'],
                                    "cf_id"     :  cv['id'],
                                    "action"    :  "delete",
                                    "account"   :  self.CF_MANAGED[k]['account'],
                                    "zone"      :  self.CF_MANAGED[k]['zone'],
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
                                "account"  :  self.CF_MANAGED[k]['account'],
                                "zone"     :  self.CF_MANAGED[k]['zone'],
                                }
                            })

                        # PTR only in one zone. No need to continue iterating
                        break

                except TypeError:
                    pass

        return out


    def _synchronize_records(self, cf_managed):
        for name, content in cf_managed.items():
            if content['action'] == 'create':
                self._create_record(name, content['ptr'], content['zone'])

            elif content['action'] == 'update':
                self._update_record(name, content['ptr'], content['zone'], content['cf_id'])

            elif content['action'] == 'delete':
                self._delete_record(name, content['ptr'], content['zone'], content['cf_id'])


    def get_cfzones(self):

        filt = {
                "type": "managed_zone",
                "provider": "cloudflare",

                }

        out = utilDB(_UTIL_COLLECTION).read(filt)

        if not out:
            raise CloudflareException(
                    code=404,
                    message='cfdns connector says: no managed zones found',
                    )

        return {
                    item['prefix'] : {
                        "account" : item['account'],
                        "zone"    : item['zone'],
                        "managed" : item['managed'],
                    }

                    for item in out
                }


    def set_cfzone(self, account, zone, prefix, managed=True):
        entry = {
                'type'     :  'managed_zone',
                'provider' :  'cloudflare',
                'account'  :  account,
                'zone'     :  zone,
                'prefix'   :  str(prefix),
                'managed'  :  managed,
                }

        filt = { "prefix": entry['prefix'], "type": "managed_zone", "provider": "cloudflare" }

        return utilDB(_UTIL_COLLECTION).replace_one(filt, entry)


    def delete_cfzone(self, prefix):

        db = utilDB(_UTIL_COLLECTION)
        filt = { "prefix": prefix, "type": "managed_zone", "provider": "cloudflare" }

        count = db.delete(filt)

        if count == 0:
            raise CloudflareException(
                    code=404,
                    message='Prefix not found in CF managed zones',
                    )

        return count


    def synchronize(self, test=True):

        data = self._get_ptrs()
        if not data:
            raise CloudflareException(
                    code=404,
                    message='No PTRs found for manages zones. Nothing updated.',
                    )

        cf_managed = self._gen_cf_managed(data)
        if cf_managed and not test:
            self._synchronize_records(cf_managed)

        return cf_managed


    def list_records(self):
        cf_managed = deepcopy(self.CF_MANAGED)

        for zone, zone_data in cf_managed.items():
            zone_data['ptrs'] = self._pull_cf_managed(self.CF_MANAGED[zone]['zone'])

        return cf_managed
