import logging, netaddr
from util.decorators import restful_method
from modules.ripe import RipeStatUtility

# Public symbols
__all__ = [
        'looking_glass',
        'get_paths',
        ]

logger = logging.getLogger(__name__)

@restful_method
def looking_glass(method, data, params):
    prefix = params.get('prefix')
    lookback = params.get('lookback')

    if not prefix:
        return False, None, 'prefix required'

    if not lookback:
        lookback = 300

    try:
        netaddr.IPNetwork(prefix)

    except netaddr.core.AddrFormatError:
        return False, None, 'Invalid prefix'

    if not ( isinstance(lookback, int) and lookback in range(60, 86401) ):
        return False, None, 'lookback out of range'

    out = RipeStatUtility().looking_glass(prefix, lookback)

    return True, out, f'RipeStat looking glass result for {prefix}'


@restful_method
def get_paths(method, data, params):
    prefix = params.get('prefix')

    if not prefix:
        return False, None, 'prefix required'

    try:
        netaddr.IPNetwork(prefix)

    except netaddr.core.AddrFormatError:
        return False, None, 'Invalid prefix'

    out = RipeStatUtility().get_paths(prefix)

    return True, out, f'RipeStat LG AS paths for {prefix}'
