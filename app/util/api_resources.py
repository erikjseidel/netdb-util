import json
from pydantic import BaseModel
from typing import Union, Any
from starlette.responses import Response

description = """
Version 2 of the NetDB Utility API. 🚀

For more information visit [netdb-util at Github](https://github.com/erikjseidel/netdb-util/)
"""


tags = [
    {
        "name": "netbox_device",
        "description": "Netbox device configuration data",
    },
    {
        "name": "netbox_interface",
        "description": " Netbox interface configuration data",
    },
    {
        "name": "netbox_igp",
        "description": "Netbox IGP (IS-IS) configuration data",
    },
    {
        "name": "netbox_ebgp",
        "description": "Netbox internal eBGP configuration data",
    },
    {
        "name": "netbox_script",
        "description": "Trigger Netbox scripts",
    },
    {
        "name": "pm_sessions",
        "description": "Endpoints for showing, adding and updating PM sesssions and loading them into NetDB",
    },
    {
        "name": "pm_policy",
        "description": "Endpoints for showing, adding and updating PM policy objects",
    },
    {
        "name": "pm_asn",
        "description": "Endpoints for showing, adding and updating PM ASN objects",
    },
    {
        "name": "repo_yaml",
        "description": "Endpoints for loading REPO YAML configuration data into NetDB",
    },
    {
        "name": "cfdns",
        "description": "Endpoints for managing and syncing CF managed DNS (PTR) records",
    },
    {
        "name": "ripe_utility",
        "description": "Utilities that make use of RIPE looking glass API",
    },
    {
        "name": "ipam_utility",
        "description": "Basic IPAM utilities",
    },
]

ERR_READONLY = {
    'result': False,
    'comment': 'NetDB Utility API is running in read only mode.',
}


class UtilityAPIReturn(BaseModel):
    result: bool = True
    error: bool = False
    out: Union[dict, list, None] = None
    comment: Union[str, None] = None


class PrettyJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            separators=(", ", ": "),
        ).encode("utf-8")
