from copy import deepcopy
from ipaddress import ip_address, ip_network
from util.decorators import restful_method
from util.utildb_api import utilDB
from modules import cfdns
from modules.cfdns import CloudflareException

__all__ = [ 
        'set_cfzone', 
        'delete_cfzone', 
        'get_cfzones',
        'set_cftoken', 
        'get_ptrs', 
        'get_cf', 
        'update_cf',
        ]

@restful_method
def set_cfzone(method, data, params):
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

    if params.get('test') in ['false', 'False']:
        filt = { "prefix": entry['prefix'], "type": "managed_zone", "provider": "cloudflare" }

        result, out, comment = utilDB(_UTIL_COLLECTION).replace_one(filt, entry)
        return result, entry, comment
    else:
        return True, entry, 'dry run: database not updated'


@restful_method(methods = ['DELETE'])
def delete_cfzone(method, data, params):
    prefix = data.get('prefix')

    try:
        ip_network(prefix)
    except ValueError:
        return False, None, 'invalid prefix'

    db = utilDB(_UTIL_COLLECTION)
    filt = { "prefix": prefix, "type": "managed_zone", "provider": "cloudflare" }

    return db.delete(filt)


@restful_method
def get_cfzones(method, data, params):
    result = cfdns.get_cfzones()

    if result:
        return True, result, 'cf managed zones'
    else:
        return False, None, 'no cf managed zones found'


@restful_method
def get_ptrs(method, data, params):
    """
    Get a list of all PTRs registered in netdb 

    :param None: No parameters for this method.
    """
    return cfdns.get_ptrs()


@restful_method
def get_cf(method, data, params):
    cf_managed = cfdns.init_cf()

    try:
        for zone, zone_data in cf_managed.items():
            zone_data['ptrs'] = cfdns.pull_cf_managed(_CF_MANAGED[zone]['zone'])

    except CloudflareException as e:
        return False, { 'url': e.url }, e.message

    return True, cf_managed, 'CF managed PTR Zones'


@restful_method
def update_cf(method, data, params):
    cfdns.init_cf()

    result, data, comment = cfdns.get_ptrs()

    if not result:
        return result, data, comment

    success = True
    try:
        cf_managed = cfdns.gen_cf_managed(data)
        if not cf_managed:
            success = False
            comment = 'All CF managed zones and records up to date.'

        elif params.get('test') in ['false', 'False']:
            cfdns.update_cf_records(cf_managed)
            comment = 'Update complete. The CF zones and records listed below have been updated.'
        else:
            comment = 'List of CF records requiring synchronisation with netdb'

    except CloudflareException as e:
        success    = False
        cf_managed = { 'url': e.url, 'data': e.data }
        comment    = e.message

    return success, cf_managed, comment
