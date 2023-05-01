import requests, json

NETDB_URL = "http://127.0.0.1:8001/api/"

HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        }


class NetdbException(Exception):
    """Exception raised for failed / unexpected netdb API calls / results

    Attributes:
        url     -- CF API url
        message -- explanation of the error
    """
    def __init__(self, url, data, message):
        self.url     = url
        self.data    = data
        self.message = message
        super().__init__(self.message)


def netdb_get(column, data=None, project=False):
    url = NETDB_URL + column

    if project:
        url += '/project'

    try:
        if data:
            ret = requests.get(url, data = json.dumps(data), headers = HEADERS ).json()
        else:
            ret = requests.get(url, headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error']:
        raise NetdbException(url, ret.get(out), ret['comment'])

    return ret['result'], ret.get('out'), ret['comment']


def netdb_validate(column, data):
    url = NETDB_URL + column + '/validate'

    try:
        ret = requests.post(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error']:
        raise NetdbException(url, ret.get(out), ret['comment'])

    return ret['result'], ret.get('out'), ret['comment']


def netdb_add(column, data):
    url = NETDB_URL + column

    try:
        ret = requests.post(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error'] or not ret['result']:
        raise NetdbException(url, ret.get(out), ret['comment'])


def netdb_replace(column, data):
    url = NETDB_URL + column

    try:
        ret = requests.put(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error'] or not ret['result']:
        raise NetdbException(url, ret.get(out), ret['comment'])


def netdb_delete(column, data):
    url = NETDB_URL + column

    try:
        ret = requests.delete(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error'] or not ret['result']:
        raise NetdbException(url, ret.get(out), ret['comment'])
