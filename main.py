import util.api_resources as resources

from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.encoders import jsonable_encoder
from util.exception import UtilityAPIException

from modules.netbox import NetboxUtility

from util.api_resources import (
        UtilityAPIReturn,
        PrettyJSONResponse,
        ERR_READONLY,
        )

app = FastAPI(
        title="NetDB API Version 2",
        description=resources.description,
        openapi_tags=resources.tags,
        )


# API base endpoints

CONNECTORS = '/connectors'
NETBOX_CONNECTOR = f'{CONNECTORS}/netbox/'


# List of available netbox script endpoints mapped to netbox script names.

NETBOX_SCRIPTS = {
        'update_iface_descriptions' : 'update_iface_descriptions.UpdateIfaceDescriptions',
        'update_ptrs' : 'update_ptrs.UpdatePTRs',
        'renumber' : 'renumber.GenerateNew',
        'prune_ips' : 'renumber.PruneIPs',
        'create_pni' : 'add_pni.CreatePNI',
        'create_bundle': 'add_pni.CreateBundle',
        'configure_pni': 'add_pni.ConfigurePNI',
        }


#-----------------------------------------------------------------------------------
#
#   Exception Handlers and root endpoint
#
#-----------------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
   errors = exc.errors()
   response = jsonable_encoder(
           UtilityAPIReturn(
               result=False,
               out={ 'detail': errors },
               comment='NetDB Utility says: FastAPI returned a validation error.',
               )
           )

   return PrettyJSONResponse(content=response, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


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
   response = jsonable_encoder(
           UtilityAPIReturn(
               result=False,
               error=True,
               out=exc.data,
               comment=exc.message,
               ),
           exclude_none=True,
           )

   return PrettyJSONResponse(content=response, status_code=exc.code)


@app.get("/")
def read_root():
    return {
            'name'    : 'NetDB Utility API version 2',
            'status'  : 'up',
            }


#-----------------------------------------------------------------------------------
#
#   Netbox connector entry points
#
#-----------------------------------------------------------------------------------

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
            out=NetboxUtility().generate_devices(),
            comment='Devices generated from Netbox datasource',
            )


@app.post(
        NETBOX_CONNECTOR + 'device',
        tags=['netbox_device'],
        response_class=PrettyJSONResponse,
        )
def netbox_reload_devices(response: Response):
    return UtilityAPIReturn(
            out=NetboxUtility().reload_devices(),
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
            out=NetboxUtility().generate_interfaces(),
            comment='Interfaces generated from Netbox datasource',
            )


@app.post(
        NETBOX_CONNECTOR + 'interface',
        tags=['netbox_interface'],
        response_class=PrettyJSONResponse,
        )
def netbox_reload_interfaces(response: Response):
    return UtilityAPIReturn(
            out=NetboxUtility().reload_interfaces(),
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
            out=NetboxUtility().generate_igp(),
            comment='IGP configuration generated from Netbox datasource',
            )


@app.post(
        NETBOX_CONNECTOR + 'igp',
        tags=['netbox_igp'],
        response_class=PrettyJSONResponse,
        )
def netbox_reload_igp(response: Response):
    return UtilityAPIReturn(
            out=NetboxUtility().reload_igp(),
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
            out=NetboxUtility().generate_ebgp(),
            comment='eBGP configuration generated from Netbox datasource',
            )


@app.post(
        NETBOX_CONNECTOR + 'ebgp',
        tags=['netbox_ebgp'],
        response_class=PrettyJSONResponse,
        )
def netbox_reload_ebgp(response: Response):
    return UtilityAPIReturn(
            out=NetboxUtility().reload_ebgp(),
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

    result, out, comment = NetboxUtility(test).script_runner(NETBOX_SCRIPTS[script], data)

    return UtilityAPIReturn(
            result=result,
            out=out,
            comment=comment,
            )
