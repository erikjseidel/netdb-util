import logging
from util.decorators import restful_method
from modules.pm import PeeringManagerUtility, PMException

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

logger = logging.getLogger(__name__)

@restful_method
def generate_direct_sessions(method, data, params):
    try:
        data = PeeringManagerUtility().generate_direct_sessions()

    except PMException as e:
        logger.error(f'exception at pm.generate_direct_sessions: {e.message}', exc_info=e)
        return False, e.data, e.message

    return True, data, 'eBGP direct sessions generated from Peering Manager datasource'


@restful_method
def generate_ixp_sessions(method, data, params):
    try:
        data = PeeringManagerUtility().generate_ixp_sessions()

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
        data = PeeringManagerUtility().generate_session(device, ip)

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
        return PeeringManagerUtility(test).synchronize_sessions()
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
        return PeeringManagerUtility(test).synchronize_session(device, ip)
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
        return PeeringManagerUtility().set_status(device, ip, status)

    except PMException as e:
        logger.error(f'exception at pm.set_maintenance: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def create_policy(method, data, params):

    try:
        return PeeringManagerUtility().create_policy(data)

    except PMException as e:
        logger.error(f'exception at pm.create_policy: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['DELETE'])
def delete_policy(method, data, params):
    name = params.get('name')

    if not  isinstance(name, str):
        return False, None, 'name parameter required'

    try:
        return PeeringManagerUtility().delete_policy(name)

    except PMException as e:
        logger.error(f'exception at pm.delete_policy: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def create_asn(method, data, params):

    try:
        return PeeringManagerUtility().create_asn(data)

    except PMException as e:
        logger.error(f'exception at pm.create_asn: {e.message}', exc_info=e)
        return False, e.data, e.message


@restful_method(methods=['POST'])
def peeringdb_asn_sync(method, data, params):
    asn = params.get('asn')

    if not asn:
        return False, None, 'asn parameter required'

    try:
        return PeeringManagerUtility().peeringdb_asn_sync(int(asn))

    except PMException as e:
        logger.error(f'exception at pm.peeringdb_asn_sync: {e.message}', exc_info=e)
        return False, e.data, e.message
