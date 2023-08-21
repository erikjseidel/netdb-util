import logging
from util.decorators import restful_method
from modules.pm import PeeringManagerUtility

# Public symbols
__all__ = [
        'generate_direct_sessions',
        'generate_ixp_sessions',
        'generate_session',
        'reload_ebgp',
        'reload_session',
        'set_status',
        'create_policy',
        'delete_policy',
        'create_asn',
        'peeringdb_asn_sync',
        'create_direct_session',
        'update_direct_session',
        'delete_direct_session',
        ]

logger = logging.getLogger(__name__)

@restful_method
def generate_direct_sessions(method, data, params):

    data = PeeringManagerUtility().generate_direct_sessions()

    return True, data, 'eBGP direct sessions generated from Peering Manager datasource'


@restful_method
def generate_ixp_sessions(method, data, params):

    data = PeeringManagerUtility().generate_ixp_sessions()

    return True, data, 'eBGP IXP sessions generated from Peering Manager datasource'


@restful_method
def generate_session(method, data, params):
    device = params.get('device')
    ip = params.get('ip')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    data = PeeringManagerUtility().generate_session(device, ip)

    msg = f'eBGP session not found'
    if data:
        msg = 'eBGP session generated from Peering Manager datasource'

    return bool(data), data, msg


@restful_method(methods=['POST'])
def reload_ebgp(method, data, params):
    data = PeeringManagerUtility().reload_ebgp()

    return True, data, 'eBGP data reloaded into column from Peering Manager datasource'


@restful_method(methods=['POST'])
def reload_session(method, data, params):
    device = params.get('device')
    ip = params.get('ip')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    data = PeeringManagerUtility().reload_session(device, ip)

    return True, data, 'eBGP session reloaded into column from Peering Manager datasource'


@restful_method(methods=['PUT'])
def set_status(method, data, params):
    device = params.get('device')
    ip = params.get('ip')
    status = params.get('status')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    return PeeringManagerUtility().set_status(device, ip, status)


@restful_method(methods=['POST'])
def create_policy(method, data, params):

    return PeeringManagerUtility().create_policy(data)


@restful_method(methods=['DELETE'])
def delete_policy(method, data, params):
    name = params.get('name')

    if not  isinstance(name, str):
        return False, None, 'name parameter required'

    return PeeringManagerUtility().delete_policy(name)


@restful_method(methods=['POST'])
def create_asn(method, data, params):

    return PeeringManagerUtility().create_asn(data)


@restful_method(methods=['POST'])
def peeringdb_asn_sync(method, data, params):
    asn = params.get('asn')

    if not asn:
        return False, None, 'asn parameter required'

    return PeeringManagerUtility().peeringdb_asn_sync(int(asn))


@restful_method(methods=['POST'])
def create_direct_session(method, data, params):

    return PeeringManagerUtility().create_direct_session(data)


@restful_method(methods=['PUT'])
def update_direct_session(method, data, params):

    return PeeringManagerUtility().update_direct_session(data)


@restful_method(methods=['DELETE'])
def delete_direct_session(method, data, params):
    device = params.get('device')
    ip = params.get('ip')

    if not (device and ip):
        return False, None, 'device and ip parameters required'

    return PeeringManagerUtility().delete_direct_session(device, ip)
