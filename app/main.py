import util.api_resources as resources

from typing import Optional, Union
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, IPvAnyAddress, IPvAnyNetwork
from util.exception import UtilityAPIException

from modules.netbox import NetboxConnector
from modules.pm import PeeringManagerConnector
from modules.repo import RepoConnector
from modules.cfdns import CloudflareDNSConnector
from modules.ripe import RipeStatUtility
from modules import ipam

from util.api_resources import (
    UtilityAPIReturn,
    PrettyJSONResponse,
    ERR_READONLY,
)

app = FastAPI(
    title="NetDB Util API Version 2",
    description=resources.description,
    openapi_tags=resources.tags,
)


# API base endpoints

CONNECTORS = '/connectors'
PM_CONNECTOR = f'{CONNECTORS}/pm/'
REPO_CONNECTOR = f'{CONNECTORS}/repo/'
NETBOX_CONNECTOR = f'{CONNECTORS}/netbox/'
CFDNS_CONNECTOR = f'{CONNECTORS}/cfdns/'

UTILITY = '/utility'
RIPE_UTILITY = f'{UTILITY}/ripe/'
IPAM_UTILITY = f'{UTILITY}/ipam/'


# List of available netbox script endpoints mapped to netbox script names.

NETBOX_SCRIPTS = {
    'update_iface_descriptions': 'update_iface_descriptions.UpdateIfaceDescriptions',
    'update_ptrs': 'update_ptrs.UpdatePTRs',
    'renumber': 'renumber.GenerateNew',
    'prune_ips': 'renumber.PruneIPs',
    'create_pni': 'add_pni.CreatePNI',
    'create_bundle': 'add_pni.CreateBundle',
    'configure_pni': 'add_pni.ConfigurePNI',
}


# -----------------------------------------------------------------------------------
#
#   Exception Handlers and root endpoint
#
# -----------------------------------------------------------------------------------


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    response = jsonable_encoder(
        UtilityAPIReturn(
            result=False,
            out={'detail': errors},
            comment='NetDB Utility says: FastAPI returned a validation error.',
        )
    )

    return PrettyJSONResponse(
        content=response, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
    )


@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    response = jsonable_encoder(
        UtilityAPIReturn(
            result=False,
            error=True,
            comment='NetDB Utility resource not found.',
        ),
        exclude_none=True,
    )

    return PrettyJSONResponse(content=response, status_code=status.HTTP_404_NOT_FOUND)


@app.exception_handler(UtilityAPIException)
async def utility_api_exception_handler(request: Request, exc: UtilityAPIException):
    error = True
    if exc.code in [200, 404]:
        error = False

    response = jsonable_encoder(
        UtilityAPIReturn(
            result=False,
            error=error,
            out=exc.data,
            comment=exc.message,
        ),
        exclude_none=True,
    )

    return PrettyJSONResponse(content=response, status_code=exc.code)


@app.get("/")
def read_root():
    return {
        'name': 'NetDB Utility API version 2',
        'status': 'up',
    }


# -----------------------------------------------------------------------------------
#
#   Netbox connector entry points
#
# -----------------------------------------------------------------------------------


#
# Netbox Device generation endpoints
#
@app.get(
    NETBOX_CONNECTOR + 'device',
    tags=['netbox_device'],
    response_class=PrettyJSONResponse,
)
def netbox_generate_devices(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().generate_devices(),
        comment='Devices generated from Netbox datasource',
    )


@app.post(
    NETBOX_CONNECTOR + 'device',
    tags=['netbox_device'],
    response_class=PrettyJSONResponse,
)
def netbox_reload_devices(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().reload_devices(),
        comment='Device configuration reloaded from Netbox datasource',
    )


#
# Netbox Interface generation endpoints
#
@app.get(
    NETBOX_CONNECTOR + 'interface',
    tags=['netbox_interface'],
    response_class=PrettyJSONResponse,
)
def netbox_generate_interfaces(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().generate_interfaces(),
        comment='Interfaces generated from Netbox datasource',
    )


@app.post(
    NETBOX_CONNECTOR + 'interface',
    tags=['netbox_interface'],
    response_class=PrettyJSONResponse,
)
def netbox_reload_interfaces(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().reload_interfaces(),
        comment='Interface configuration reloaded from Netbox datasource',
    )


#
# Netbox IGP generation endpoints
#
@app.get(
    NETBOX_CONNECTOR + 'igp',
    tags=['netbox_igp'],
    response_class=PrettyJSONResponse,
)
def netbox_generate_igp(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().generate_igp(),
        comment='IGP configuration generated from Netbox datasource',
    )


@app.post(
    NETBOX_CONNECTOR + 'igp',
    tags=['netbox_igp'],
    response_class=PrettyJSONResponse,
)
def netbox_reload_igp(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().reload_igp(),
        comment='IGP configuration reloaded from Netbox datasource',
    )


#
# Netbox eBGP generation endpoints
#
@app.get(
    NETBOX_CONNECTOR + 'ebgp',
    tags=['netbox_ebgp'],
    response_class=PrettyJSONResponse,
)
def netbox_generate_ebgp(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().generate_ebgp(),
        comment='eBGP configuration generated from Netbox datasource',
    )


@app.post(
    NETBOX_CONNECTOR + 'ebgp',
    tags=['netbox_ebgp'],
    response_class=PrettyJSONResponse,
)
def netbox_reload_ebgp(response: Response):
    return UtilityAPIReturn(
        out=NetboxConnector().reload_ebgp(),
        comment='eBGP configuration reloaded from Netbox datasource',
    )


#
# Netbox script runner endpoints
#


@app.post(
    NETBOX_CONNECTOR + 'script/{script}',
    tags=['netbox_script'],
    response_class=PrettyJSONResponse,
)
def netbox_script(
    script: str,
    response: Response,
    test: bool = True,
    data: dict = {},
):
    if script not in NETBOX_SCRIPTS.keys():
        raise UtilityAPIException(
            code=404,
            message=f'Netbox script "{script}" not available.',
        )

    ret = NetboxConnector(test).script_runner(NETBOX_SCRIPTS[script], data)

    return UtilityAPIReturn(
        result=ret['result'],
        out=ret.get('out'),
        comment=ret.get('comment'),
    )


# -----------------------------------------------------------------------------------
#
#   Peering Manager connector entry points
#
# -----------------------------------------------------------------------------------

#
# Peering Manager session generation endpoints
#


@app.get(
    PM_CONNECTOR + 'sessions/direct',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_generate_direct_sessions(response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().generate_direct_sessions(),
        comment=f'PM direct eBGP sessions',
    )


@app.post(
    PM_CONNECTOR + 'sessions/direct',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_create_direct_session(data: dict, response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().create_direct_session(data),
        comment='Direct session added to PM',
    )


@app.put(
    PM_CONNECTOR + 'sessions/direct',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_update_direct_session(data: dict, response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().update_direct_session(data),
        comment='Direct session updated in PM',
    )


@app.delete(
    PM_CONNECTOR + 'sessions/direct',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_delete_direct_session(device: str, ip: IPvAnyAddress, response: Response):
    PeeringManagerConnector().delete_direct_session(device, ip)

    return UtilityAPIReturn(
        comment='Direct session deleted from PM',
    )


@app.get(
    PM_CONNECTOR + 'sessions/ixp',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_generate_ixp_sessions(response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().generate_ixp_sessions(),
        comment=f'PM IXP eBGP sessions',
    )


@app.post(
    PM_CONNECTOR + 'sessions/reload',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_reload_sessions(response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().reload_ebgp(),
        comment=f'PM eBGP sessions reloaded',
    )


@app.put(
    PM_CONNECTOR + 'sessions/status',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_update_session_status(
    device: str,
    ip: IPvAnyAddress,
    status: str,
    response: Response,
):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().set_status(device, str(ip), status),
        comment='Status changed',
    )


# Single session reload


class PMDeviceIP(BaseModel):
    device: str
    ip: IPvAnyAddress


@app.post(
    PM_CONNECTOR + 'sessions/reload/single',
    tags=['pm_sessions'],
    response_class=PrettyJSONResponse,
)
def pm_reload_single_session(data: PMDeviceIP, response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().reload_session(data.device, str(data.ip)),
        comment=f'PM eBGP session reloaded for {data.ip} at {data.device}',
    )


#
# Peering Manager policy endpoints
#


@app.post(
    PM_CONNECTOR + 'policy',
    tags=['pm_policy'],
    response_class=PrettyJSONResponse,
)
def pm_create_policy(data: dict, response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().create_policy(data),
        comment='Policy created in Peering Manager',
    )


@app.delete(
    PM_CONNECTOR + 'policy',
    tags=['pm_policy'],
    response_class=PrettyJSONResponse,
)
def pm_delete_policy(name: str, response: Response):
    PeeringManagerConnector().delete_policy(name)

    return UtilityAPIReturn(
        comment=f'Policy {name} deleted from Peering Manager',
    )


#
# Peering Manager ASN endpoints
#


@app.post(
    PM_CONNECTOR + 'asn',
    tags=['pm_asn'],
    response_class=PrettyJSONResponse,
)
def pm_create_asn(data: dict, response: Response):
    return UtilityAPIReturn(
        out=PeeringManagerConnector().create_asn(data),
        comment='ASN created in Peering Manager',
    )


@app.post(
    PM_CONNECTOR + 'asn/{asn}/sync',
    tags=['pm_asn'],
    response_class=PrettyJSONResponse,
)
def pm_peeringdb_asn_sync(asn: int, response: Response):
    PeeringManagerConnector().peeringdb_asn_sync(asn)

    return UtilityAPIReturn(
        comment=f'AS{asn}: PeeringDB sync complete',
    )


# -----------------------------------------------------------------------------------
#
#   Repo YAML connector entry points
#
# -----------------------------------------------------------------------------------


@app.get(
    REPO_CONNECTOR + '{column}',
    tags=['repo_yaml'],
    response_class=PrettyJSONResponse,
)
def repo_yaml_generate_column(column: str, response: Response):
    return UtilityAPIReturn(
        out=RepoConnector().generate_column(column),
        comment='Column generated from repo_yaml',
    )


@app.post(
    REPO_CONNECTOR + '{column}',
    tags=['repo_yaml'],
    response_class=PrettyJSONResponse,
)
def repo_yaml_reload(column: str, response: Response):
    return UtilityAPIReturn(
        out=RepoConnector().reload_column(column),
        comment='Column data reloaded into netdb',
    )


# -----------------------------------------------------------------------------------
#
#   Cloudflare Managed DNS (PTR zones) connector entry points
#
# -----------------------------------------------------------------------------------


@app.get(
    CFDNS_CONNECTOR + 'records',
    tags=['cfdns'],
    response_class=PrettyJSONResponse,
)
def cfdns_list_records(response: Response):
    return UtilityAPIReturn(
        out=CloudflareDNSConnector().list_records(),
        comment='CF managed PTRs',
    )


@app.get(
    CFDNS_CONNECTOR + 'zones',
    tags=['cfdns'],
    response_class=PrettyJSONResponse,
)
def cfdns_list_zones(response: Response):
    return UtilityAPIReturn(
        out=CloudflareDNSConnector().get_cfzones(),
        comment='CF managed PTR Zones',
    )


class CFZoneInput(BaseModel):
    account: str
    zone: str
    prefix: IPvAnyNetwork
    managed: bool = True


@app.post(
    CFDNS_CONNECTOR + 'zones',
    tags=['cfdns'],
    response_class=PrettyJSONResponse,
)
def cfdns_upsert_zone(data: CFZoneInput, response: Response):
    count = CloudflareDNSConnector().set_cfzone(
        account=data.account,
        zone=data.zone,
        prefix=data.prefix,
        managed=data.managed,
    )

    return UtilityAPIReturn(
        result=bool(count),
        comment=f'{count} CF managed PTR Zone upserted.',
    )


@app.delete(
    CFDNS_CONNECTOR + 'zones',
    tags=['cfdns'],
    response_class=PrettyJSONResponse,
)
def cfdns_delete_zones(prefix: IPvAnyNetwork, response: Response):
    CloudflareDNSConnector().delete_cfzone(str(prefix))

    return UtilityAPIReturn(
        comment=f'CF DNS PTR zone for {prefix} no longer managed',
    )


@app.post(
    CFDNS_CONNECTOR + 'update',
    tags=['cfdns'],
    response_class=PrettyJSONResponse,
)
def cfdns_update_cf(response: Response, test: bool = True):
    comment = (
        'Update complete. The CF zones and records listed below have been updated.'
    )
    if test:
        comment = 'List of CF records requiring synchronisation with netdb'

    return UtilityAPIReturn(
        out=CloudflareDNSConnector().synchronize(test),
        comment=comment,
    )


# -----------------------------------------------------------------------------------
#
#   Ripe Looking Glass utility entry points
#
# -----------------------------------------------------------------------------------


@app.get(
    RIPE_UTILITY + 'lg',
    tags=['ripe_utility'],
    response_class=PrettyJSONResponse,
)
def ripe_bgp_lg(
    prefix: Union[IPvAnyNetwork, IPvAnyAddress], response: Response, lookback: int = 300
):
    return UtilityAPIReturn(
        out=RipeStatUtility().looking_glass(str(prefix)),
        comment=f'RipeStat looking glass result for {prefix}',
    )


@app.get(
    RIPE_UTILITY + 'paths',
    tags=['ripe_utility'],
    response_class=PrettyJSONResponse,
)
def ripe_bgp_paths(prefix: Union[IPvAnyNetwork, IPvAnyAddress], response: Response):
    return UtilityAPIReturn(
        out=RipeStatUtility().get_paths(str(prefix)),
        comment=f'RipeStat LG AS paths for {prefix}',
    )


# -----------------------------------------------------------------------------------
#
#   IPAM utility entry points
#
# -----------------------------------------------------------------------------------


@app.get(
    IPAM_UTILITY + 'report',
    tags=['ipam_utility'],
    response_class=PrettyJSONResponse,
)
def ipam_report(response: Response):
    return UtilityAPIReturn(
        out=ipam.report(),
        comment='Addresses and prefixes found in netdb',
    )


@app.get(
    IPAM_UTILITY + 'chooser',
    tags=['ipam_utility'],
    response_class=PrettyJSONResponse,
)
def ipam_report(prefix: IPvAnyNetwork, response: Response):
    return UtilityAPIReturn(
        out=ipam.chooser(str(prefix)),
        comment='Sub-prefixes not found in netdb',
    )
