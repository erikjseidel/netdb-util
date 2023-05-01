
from copy       import deepcopy
from netaddr    import IPSet
from ipaddress  import ip_interface, ip_network

from util.decorators import restful_method
from util.netdb      import netdb_get
from util.query      import ADDR_PROJECT

# Public symbols
__all__ = [ 'report', 'chooser' ]

_NETDB_COLUMN = 'interface'

@restful_method
def report(method, data):
    """
    Show salt managed IP addresses.

    A sorted list of salt managed IP addresses is also displayed in the
    comment.

    :param data['device']: Limit report to only the specified device (optional)
    """
    project = deepcopy(ADDR_PROJECT)

    if data and 'device' in data:
        project['filter'].update({ 'set_id': str(data['device']).upper() })

    result, data, comment = netdb_get(_NETDB_COLUMN, project, project=True)

    if not result:
        return result, None, comment

    report_data = {}

    report_text = "Salt managed addresses:\n----------\n"

    for device, interfaces in data.items():
        for iface, iface_data in interfaces['interfaces'].items():
            if 'address' in iface_data:
                for addr, addr_data in iface_data['address'].items():

                    cidr = addr.split('/')

                    report_data[cidr[0]] = {}
                    report_data[cidr[0]]['cidr'] = cidr[1]
                    report_data[cidr[0]]['device'] = device
                    report_data[cidr[0]]['interface'] = iface

                    if 'description' in iface_data:
                        report_data[cidr[0]]['description'] = iface_data['description']

                    if 'meta' in addr_data:
                        report_data[cidr[0]]['meta'] = deepcopy(addr_data['meta'])

    out = report_data

    iplist = list(report_data.keys())

    for ip in iplist:
        description = ""
        if 'description' in report_data[ip]:
            description = report_data[ip]['description']

        report_text += "{0:30} {1:10} {2:10} {3:40}\n".format(ip + '/' + report_data[ip]['cidr'], report_data[ip]['device'],
                report_data[ip]['interface'], description)

    comment = report_text
    result  =  True

    return result, out, comment


@restful_method
def chooser(method, data):
    """
    Show available prefixes / free IP space within a given (super)prefix.
    In order for this function to by accurate, all IP a space within the
    the queried prefix must be managed by netdb - salt.

    :param: data['prefix']: The prefix whose free space is to be returned.
    """

    if 'prefix' in data:
        prefix = data['prefix']
    else:
        return False, None, 'Prefix is required'

    try:
        network = ip_network(prefix)
    except:
        return False, None, 'Invalid prefix'

    result, data, comment = netdb_get(_NETDB_COLUMN, ADDR_PROJECT, project=True)

    if not result or not data:
        return result, data, comment

    prefix_list = []
    avail_addr = []

    for device, interfaces in data.items():
        for iface, iface_data in interfaces['interfaces'].items():
            if 'address' in iface_data:
                addresses = iface_data['address'].keys()
                for addr in addresses:
                    net = ip_interface(addr).network
                    try:
                        if net.subnet_of(network) and str(net) not in prefix_list:
                            prefix_list.append(str(net))
                    except:
                        continue

    available = IPSet( [str(network)] ) ^ IPSet(prefix_list)

    comment = "Available prefixes:\n-----\n"
    out = {}
    for cidr in available.iter_cidrs():
        prefix = str(cidr)
        start  = str(cidr[0])
        end    = str(cidr[-1])

        out[prefix] = {
                'start':  start,
                'end':    end,
                }

        comment += "%s [%s - %s]\n" % ( prefix, start, end )

    return True, out, comment
