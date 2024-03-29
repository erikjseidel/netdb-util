import requests, json, logging, netaddr
from util.exception import UtilityAPIException

logger = logging.getLogger(__name__)


class RipeStatException(UtilityAPIException):
    pass


class RipeStatAPI:
    """
    Simple class for interacting with RIPE Stats.
    """

    _API_BASE = "https://stat.ripe.net/data"

    _HEADERS = {
        'Content-Type': 'application/json',
    }

    ENDPOINTS = {
        'looking-glass': 'looking-glass/data.json',
    }

    def __init__(self, endpoint=None):
        self.set(endpoint)

    def set(self, endpoint):
        self.url = self._API_BASE

        if endpoint in self.ENDPOINTS.keys():
            endpoint = self.ENDPOINTS[endpoint]

        if endpoint:
            if not endpoint.startswith('/'):
                self.url += '/'

            self.url += endpoint
        return self

    def set_url(self, url):
        self.url = url
        return self

    def set_params(self, **kwargs):
        suffix = '?'

        for k, v in kwargs.items():
            if v:
                suffix += '%s=%s&' % (k, v)

        # clean up url suffix
        if suffix.endswith('?') or suffix.endswith('&'):
            suffix = suffix[:-1]

        self.url += suffix

        return self

    def get_url(self):
        return self.url

    def get(self):
        url = self.url
        logger.debug(f'RipeStat.get: {url}')

        resp = requests.get(url, headers=self._HEADERS)

        if (code := resp.status_code) != 200:
            raise RipeStatException(url, resp.json(), code)

        return resp.json()


class RipeStatUtility:
    def __init__(self, test=False):
        self.rs_api = RipeStatAPI()

    def looking_glass(self, prefix, lookback=300):
        return (
            self.rs_api.set('looking-glass')
            .set_params(resource=prefix, look_back_limit=lookback)
            .get()
        )

    def get_paths(self, prefix):
        as_paths = {}

        result = self.looking_glass(prefix)

        rrcs = result['data']['rrcs']

        if len(rrcs) > 0:
            for rrc in rrcs:
                for peer in rrc['peers']:
                    if peer['as_path'] in as_paths:
                        as_paths[peer['as_path']] += 1
                    else:
                        as_paths[peer['as_path']] = 1

        entry = {
            'datasource': 'ripestat',
            'as_paths': as_paths,
        }

        return {prefix: entry}
