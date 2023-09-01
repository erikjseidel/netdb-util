import requests, json, logging
from util.web_api import WebAPIException
from config.secrets import NETDB_URL

HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        }

logger = logging.getLogger(__name__)

def _call_netdb(url, method, data=None, params=None):

    ret = requests.request(
            url=url,
            method=method,
            json=data,
            params=params,
            headers=HEADERS
            )

    if ret.status_code in [404, 422]:
        answer = ret.json()

        raise WebAPIException(url, ret.status_code, answer.get('out'), answer['comment'])

    if ret.status_code != 200:
        raise WebAPIException(url, 503, message='Invalid netdb response: \n{}'.format(ret))

    return ret.json()


def get(column, params=None, endpoint=None):
    url = f'{NETDB_URL}column/{column}'

    if endpoint:
        url += '/' + endpoint
    
    logger.debug(f'_netdb_get: { url }')

    return _call_netdb(url=url, method='GET', params=params)


def validate(column, data):
    url = f'{NETDB_URL}validate/{column}'

    logger.debug(f'_netdb_validate: { url }')

    return _call_netdb(url=url, method='POST', data=data).get('out')


def reload(column, data):
    if not data:
        raise WebAPIException(message=f'Empty result! Column {column} not reloaded')

    url = f'{NETDB_URL}column'

    data['column_type'] = column

    logger.debug(f'_netdb_reload: { url }')

    _call_netdb(url=url, method='POST', data=data)

    return data


def replace(column, data):
    if not data:
        raise WebAPIException(message=f'Empty input! Nothing replaced.')

    url = f'{NETDB_URL}column'

    data['column_type'] = column

    logger.debug(f'_netdb_replace: { url }')

    _call_netdb(url=url, method='PUT', data=data)

    return data


def delete(column, params):
    url = f'{NETDB_URL}column/{column}'

    logger.debug(f'netdb_delete: { url }')

    _call_netdb(url=url, method='DELETE', params=params)
