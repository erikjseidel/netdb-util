import requests, json, logging
from util.web_api import WebAPIException

NETDB_URL = "http://127.0.0.1:8001/api/"

HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        }

logger = logging.getLogger(__name__)

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


def get(column, data=None, endpoint=None, project=False):
    url = NETDB_URL + column

    if endpoint:
        url += '/' + endpoint
    elif project:
        url += '/project'
    
    logger.debug(f'_netdb_get: { url }')

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


def validate(column, data):
    url = NETDB_URL + column + '/validate'

    logger.debug(f'_netdb_validate: { url }')

    try:
        ret = requests.post(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error']:
        raise NetdbException(url, ret.get(out), ret['comment'])

    return ret['result'], ret.get('out'), ret['comment']


def add(column, data):
    url = NETDB_URL + column

    logger.debug(f'_netdb_add: { url }')

    try:
        ret = requests.post(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, data, 'Invalid netdb response')

    if ret['error'] or not ret['result']:
        raise NetdbException(url, ret.get('out'), ret['comment'])


def _reload(column, data):
    url = NETDB_URL + column + '/reload/' + data['datasource']

    logger.debug(f'_netdb_reload: { url }')

    try:
        ret = requests.post(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise NetdbException(url, None, 'Invalid netdb response')

    if ret.get('error') or not ret['result']:
        raise NetdbException(url, ret.get('out'), ret['comment'])


def reload(column, data):
    if not data:
        raise WebAPIException(message=f'Empty result! Column {column} not reloaded')

    try:
        _reload(column, data)
    except NetdbException as e:
        raise WebAPIException(data=e.data, message=e.message)

    return data


def replace(column, data):
    if not data:
        raise WebAPIException(message=f'Empty result! Nothing replaced.')

    url = NETDB_URL + column

    logger.debug(f'_netdb_replace: { url }')

    try:
        ret = requests.put(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise WebAPIException(message='Invalid netdb response')

    if ret.get('error') or not ret['result']:
        raise WebAPIException(data=ret.get('out'), message=ret['comment'])

    return data


def delete(column, data):
    url = NETDB_URL + column

    logger.debug(f'netdb_delete: { url }')

    try:
        ret = requests.delete(url, data = json.dumps(data), headers = HEADERS).json()
    except Exception:
        raise WebAPIException(message='Invalid netdb response')

    if ret.get('error') or not ret['result']:
        raise WebAPIException(data=ret.get('out'), message=ret['comment'])
