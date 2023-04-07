import requests, json

from util.decorators import netdb_consumer

NETDB_URL = "http://127.0.0.1:8001/api/"

HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        }

@netdb_consumer
def netdb_get(column, data=None):
    url = NETDB_URL + column

    if data:
        return requests.get(url, data = json.dumps(data), headers = HEADERS )
    else:
        return requests.get(url, headers = HEADERS)


@netdb_consumer
def netdb_post(column, data=None):
    url = NETDB_URL + column

    if data:
        return requests.post(url, data = json.dumps(data), headers = HEADERS )
    else:
        return requests.post(url, headers = HEADERS)
