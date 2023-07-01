import logging, netaddr
from util.decorators import restful_method
from modules.ripe import RipeStatUtility

# Public symbols
__all__ = [
        'looking_glass',
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

    return RipeStatUtility().looking_glass(prefix, lookback)
