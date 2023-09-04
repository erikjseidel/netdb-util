from copy import deepcopy
from netaddr import IPSet
from ipaddress import ip_interface, ip_network
from util import netdb
from util.exception import UtilityAPIException

_NETDB_COLUMN = 'interface'

def report():
    """
    Show salt managed IP addresses.

    A sorted list of salt managed IP addresses is also displayed in the
    comment.

    :param data['device']: Limit report to only the specified device (optional)
    """
    data = netdb.get(_NETDB_COLUMN)['out']

    if not data:
        raise UtilityAPIException(
                code=404,
                message='Empty data set returned',
                )

    report_data = {}

    for device, interfaces in data.items():
        for iface, iface_data in interfaces.items():
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

    return report_data


def chooser(prefix):
    """
    Show available prefixes / free IP space within a given (super)prefix.
    In order for this function to by accurate, all IP a space within the
    the queried prefix must be managed by netdb - salt.

    :param: data['prefix']: The prefix whose free space is to be returned.
    """
    data = netdb.get(_NETDB_COLUMN)['out']

    prefix_list = []
    avail_addr = []

    network = ip_network(prefix)

    for device, interfaces in data.items():
        for iface, iface_data in interfaces.items():
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

    out = {}
    for cidr in available.iter_cidrs():
        prefix = str(cidr)
        start  = str(cidr[0])
        end    = str(cidr[-1])

        out[prefix] = {
                'start':  start,
                'end':    end,
                }

    return out
