import json
from pydantic import BaseModel
from typing import Union, Any
from starlette.responses import Response

description = """
Version 2 of the NetDB Utility API. 🚀

For more information visit [NetDB at Github](https://github.com/erikjseidel/netdb/)
"""


tags = [
    {
        "name": "list_columns",
        "description": "show a list of available columns",
    },
    {
        "name": "column",
        "description": "endpoints and methods for querying and manipulating column data",
    },
    {
        "name": "device",
        "description": "show a single set (e.g. device configuration) in a column",
    },
    {
        "name": "validate",
        "description": "validates an NetDBContainer configuration dataset without loading it",
    },
]

ERR_READONLY = {
        'result' : False,
        'comment' : 'NetDB Utility API is running in read only mode.',
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
