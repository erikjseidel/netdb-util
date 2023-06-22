#import requests, json, logging, time, yaml, ipaddress
import logging
from util import netdb

_NETDB_BGP_COLUMN   = 'bgp'

logger = logging.getLogger(__name__)

def bgp_sessions(datasource, sot_sessions, test=True):
    _FILTER = { 'datasource': datasource }

    result, out, message = netdb.validate(_NETDB_BGP_COLUMN, data = sot_sessions)
    if not result:
        return result, out, message

    result, netdb_ebgp, _ = netdb.get(_NETDB_BGP_COLUMN, data = _FILTER)
    if not result:
        netdb_ebgp = {}

    # A somewhat nasty workaround. If all neighbors removed from PM router make sure they
    # are still processed by the deletion.
    for device in netdb_ebgp.keys():
        if not sot_sessions.get(device):
            sot_sessions[device] = {}

    all_changes = {}
    adjective = 'required' if test else 'complete'

    # Apply to netdb
    for device, ebgp_data in sot_sessions.items():
        changes  = {}
        for neighbor, data in ebgp_data.get('neighbors', {}).items():
            if netdb_ebgp.get(device) and neighbor in netdb_ebgp[device]['neighbors'].keys():
                if data != netdb_ebgp[device]['neighbors'][neighbor]:
                    # Update required.
                    if not test:
                        netdb.replace(_NETDB_BGP_COLUMN, data = { device: { 'neighbors' : { neighbor: data }}})
                    changes[neighbor] = {
                            '_comment': f'update {adjective}',
                            **data
                            }
                netdb_ebgp[device]['neighbors'].pop(neighbor)
            else:
                # Addition required
                if not test:
                    netdb.add(_NETDB_BGP_COLUMN, data = { device: { 'neighbors' : { neighbor: data }}})
                changes[neighbor] = {
                        '_comment': f'addition {adjective}',
                        **data
                        }

        # Any remaining (unpopped) interfaces in netdb need to be deleted
        if device in netdb_ebgp.keys():
            for neighbor in netdb_ebgp[device]['neighbors'].keys():
                # Deletion required
                if not test:
                    filt = { "set_id": [device, 'neighbors', neighbor], **_FILTER }
                    netdb.delete(_NETDB_BGP_COLUMN, data = filt)
                changes[neighbor] = {
                       '_comment': f'removal from netdb {adjective}',
                       }

        if changes:
            all_changes[device] = {}
            all_changes[device]['neighbors'] = changes

    if not all_changes:
        message = 'Netdb eBGP sessions already synchronized. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    if not test:
        logger.info(f'_synchronize_ebgp: {message}')

    return True if all_changes else False, all_changes, message


def bgp_session(datasource, sot_session, device, ip, test=True):
    _FILTER = { 'datasource': datasource }

    result, netdb_ebgp, _ = netdb.get(_NETDB_BGP_COLUMN, data = _FILTER)
    if not netdb_ebgp.get(device):
        data = None
    else:
        data = netdb_ebgp[device]['neighbors'].get(ip)

    adjective = 'required' if test else 'complete'

    change = None
    if sot_session:
        result, out, message = netdb.validate(_NETDB_BGP_COLUMN, data = sot_session)
        if not result:
            return result, out, message

        if data:
            if data != sot_session[device]['neighbors'][ip]:
                # Update required.
                if not test:
                    netdb.replace(_NETDB_BGP_COLUMN, data = sot_session)
                change = {
                        '_comment': f'update {adjective}',
                        **sot_session[device]['neighbors']
                        }

        else:
            # Addition required
            if not test:
                netdb.add(_NETDB_BGP_COLUMN, data = sot_session)
            change = {
                    '_comment': f'addition {adjective}',
                    **sot_session[device]['neighbors']
                    }

    elif data:
        # Deletion required
        if not test:
            filt = { "set_id": [device, 'neighbors', ip], **_FILTER }
            netdb.delete(_NETDB_BGP_COLUMN, data = filt)
        change = {
               '_comment': f'removal from netdb {adjective}',
               }

    if not change:
        message = 'Netdb eBGP session already synchronized. No changes made.'
    elif test:
        message = 'Dry run. No changes made.'
    else:
        message = 'Synchronization complete.'

    if not test:
        logger.info(f'_synchronize_ebgp: {message}')

    return True if change else False, change, message
