from copy       import deepcopy
from netaddr    import IPSet
from ipaddress  import ip_interface, ip_network

from util.decorators import restful_method
from util.netdb      import netdb_get
from util.query      import DNS_PROJECT

_NETDB_COLUMN = 'interface'

@restful_method
def get_ptrs(method, data):
    """
    Get a list of all PTRs registered in netdb 

    :param None: No parameters for this method.
    """

    result, data, comment = netdb_get(_NETDB_COLUMN, DNS_PROJECT, project=True)

    if not result:
        return False, None, comment

    dns =   { 
                k[0].split('/')[0]: k[1]['meta']['dns']['ptr'] 
                    if 'ptr' in k[1]['meta']['dns'] else None 
                for i in data 
                for j in data[i]['interfaces']
                for k in data[i]['interfaces'][j]['address'].items()
            }
            
    return True, dns, 'Test'
