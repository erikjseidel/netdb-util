import logging
from util import netdb

_NETDB_DEV_COLUMN   = 'device'
_NETDB_IFACE_COLUMN = 'interface'
_NETDB_IGP_COLUMN   = 'igp'
_NETDB_BGP_COLUMN   = 'bgp'

_MSG_NO_CHANGES = 'Netdb already synchronized.'
_MSG_DRY_RUN    = 'Dry run. No changes made.'
_MSG_COMPLETE   = 'Synchronization complete.'

_MSG_UPDATE = 'update to netdb %s'
_MSG_ADD    = 'addition to netdb %s'
_MSG_DELETE = 'removal from netdb %s'

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
                            '_comment': _MSG_UPDATE % adjective,
                            **data
                            }
                netdb_ebgp[device]['neighbors'].pop(neighbor)
            else:
                # Addition required
                if not test:
                    netdb.add(_NETDB_BGP_COLUMN, data = { device: { 'neighbors' : { neighbor: data }}})
                changes[neighbor] = {
                        '_comment': _MSG_ADD % adjective,
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
                       '_comment': _MSG_DELETE % adjective,
                       }

        if changes:
            all_changes[device] = {}
            all_changes[device]['neighbors'] = changes

    if not all_changes:
        message = _MSG_NO_CHANGES
    elif test:
        message = _MSG_DRY_RUN
    else:
        message = _MSG_COMPLETE

    if not test:
        logger.info(f'synchronizers.bgp_sessions: {message}')

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
                        '_comment': _MSG_UPDATE % adjective,
                        **sot_session
                        }

        else:
            # Addition required
            if not test:
                netdb.add(_NETDB_BGP_COLUMN, data = sot_session)
            change = {
                    '_comment': _MSG_ADD % adjective,
                    **sot_session
                    }

    elif data:
        # Deletion required
        if not test:
            filt = { "set_id": [device, 'neighbors', ip], **_FILTER }
            netdb.delete(_NETDB_BGP_COLUMN, data = filt)
        change = {
               '_comment': _MSG_DELETE % adjective,
               }

    if not change:
        message = _MSG_NO_CHANGES
    elif test:
        message = _MSG_DRY_RUN
    else:
        message = _MSG_COMPLETE

    if not test:
        logger.info(f'synchronizers.bgp_session: {message}')

    return True if change else False, change, message


def igp(datasource, sot_igp, test = True):
    _FILTER = { 'datasource': datasource }

    result, out, message = netdb.validate(_NETDB_IGP_COLUMN, data = sot_igp)
    if not result:
        return result, out, message

    result, netdb_igp, _ = netdb.get(_NETDB_IGP_COLUMN, data = _FILTER)
    if not result:
        netdb_igp = {}

    changes = {}

    adjective = 'required' if test else 'complete'

    for device, data in sot_igp.items():
        if device in netdb_igp.keys():
            if data != netdb_igp[device]:
                # Update required.
                changes[device] = _MSG_UPDATE % adjective
                if not test:
                    netdb.replace(_NETDB_IGP_COLUMN, data = { device : data })
            netdb_igp.pop(device)
        else:
            # Addition required
            if not test:
                netdb.add(_NETDB_IGP_COLUMN, data = { device : data })
            changes[device] = _MSG_ADD % adjective

    # Any remaining (unpopped) devices in netdb need to be deleted
    for device in netdb_igp.keys():
        # Deletion required
        if not test:
            filt = { "set_id": [device, 'isis'], **_FILTER }
            netdb.delete(_NETDB_IGP_COLUMN, data = filt)
        changes[device] = _MSG_DELETE % adjective

    if not changes:
        message = _MSG_NO_CHANGES
    elif test:
        message = _MSG_DRY_RUN
    else:
        message = _MSG_COMPLETE

    if not test:
        logger.info(f'synchronizers.igp: {message}')

    return True if changes else False, changes, message


def interfaces(datasource, sot_interfaces, test=True):
    _FILTER = { 'datasource': datasource }

    result, out, message = netdb.validate(_NETDB_IFACE_COLUMN, data = sot_interfaces)
    if not result:
        return result, out, message

    result, netdb_ifaces, message = netdb.get(_NETDB_IFACE_COLUMN, data = _FILTER )
    if not result:
        netdb_ifaces = {}

    all_changes = {}
    adjective = 'required' if test else 'complete'

    # Apply to netdb
    for device, interfaces in sot_interfaces.items():
        changes  = {}
        for iface, data in interfaces.items():
            if device in netdb_ifaces and iface in netdb_ifaces[device].keys():
                if data != netdb_ifaces[device][iface]:
                    # Update required.
                    changes[iface] = _MSG_UPDATE % adjective
                    if not test:
                        netdb.replace(_NETDB_IFACE_COLUMN, data = { device: { iface : data }})
                netdb_ifaces[device].pop(iface)
            else:
                # Addition required
                if not test:
                    netdb.add(_NETDB_IFACE_COLUMN, data = { device: { iface : data }})
                changes[iface] = _MSG_ADD % adjective

        # Any remaining (unpopped) interfaces in netdb need to be deleted
        if device in netdb_ifaces:
            for iface in netdb_ifaces[device].keys():
                # Deletion required
                if not test:
                    filt = { "set_id": [device, iface], **_FILTER }
                    netdb.delete(_NETDB_IFACE_COLUMN, data = filt)
                changes[iface] = _MSG_DELETE % adjective

        if changes:
            all_changes[device] = changes

    if not all_changes:
        message = _MSG_NO_CHANGES
    elif test:
        message = _MSG_DRY_RUN
    else:
        message = _MSG_COMPLETE

    if not test:
        logger.info(f'synchronizers.interfaces: {message}')

    return True if all_changes else False, all_changes, message


def devices(datasource, sot_dev, test = True):
    _FILTER = { 'datasource': datasource }

    result, out, message = netdb.validate(_NETDB_DEV_COLUMN, data = sot_dev)
    if not result:
        return result, out, message

    result, netdb_dev, message = netdb.get(_NETDB_DEV_COLUMN, data = _FILTER)
    if not result:
        netdb_dev = {}

    changes = {}

    adjective = 'required' if test else 'complete'

    for device, data in sot_dev.items():
        if device in netdb_dev.keys():
            if data != netdb_dev[device]:
                # Update required.
                changes[device] = _MSG_UPDATE % adjective
                if not test:
                    netdb.replace(_NETDB_DEV_COLUMN, data = { device : data })
            netdb_dev.pop(device)
        else:
            # Addition required
            if not test:
                netdb.add(_NETDB_DEV_COLUMN, data = { device : data })
            changes[device] = _MSG_ADD % adjective

    # Any remaining (unpopped) devices in netdb need to be deleted
    for device in netdb_dev.keys():
        # Deletion required
        if not test:
            filt = { "id": device, **_FILTER }
            netdb.delete(_NETDB_IFACE_COLUMN, data = filt)
        changes[device] = _MSG_DELETE % adjective

    if not changes:
        message = _MSG_NO_CHANGES
    elif test:
        message = _MSG_DRY_RUN
    else:
        message = _MSG_COMPLETE

    if not test:
        logger.info(f'_synchronize_devices: {message}')

    return True if changes else False, changes, message
