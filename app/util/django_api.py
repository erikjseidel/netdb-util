import requests, json, logging, yaml, ipaddress
from .exception import UtilityAPIException

logger = logging.getLogger(__name__)

class DjangoException(UtilityAPIException):
    pass


class DjangoAPI:
    """
    Simple class for interacting with Django APIs.
    """

    ENDPOINTS = {}

    def __init__(self, endpoint=None):
        self.clear_cache()
        self.set(endpoint)


    def clear_cache(self):
        self._GET_CACHE = {}


    def set(self, endpoint):
        self.url = self._API_BASE
        self.public_url = self._PUBLIC_API_BASE

        if endpoint in self.ENDPOINTS.keys():
            endpoint = self.ENDPOINTS[endpoint]

        if endpoint:
            if not endpoint.startswith('/'):
                self.url += '/'
                self.public_url += '/'
            if not endpoint.endswith('/'):
                endpoint += '/'
            self.url += endpoint
            self.public_url += endpoint
        return self


    def set_url(self, url):
        self.url = url
        return self


    def set_id(self, id):
        self.url += str(id) + '/'
        self.public_url += str(id) + '/'
        return self


    def set_suffix(self, suffix):
        self.url += str(suffix) + '/'
        self.public_url += str(suffix) + '/'
        return self


    def set_params(self, **kwargs):
        suffix = '?'

        tags = kwargs.pop('tags', None)

        for k, v in kwargs.items():
            if v:
                suffix += '%s=%s&' % (k, v)

        if tags:
            if isinstance(tags, list):
                for tag in tags:
                    suffix += 'tag=%s&' % tag
            else:
                suffix += 'tag=%s' % tags

        # clean up url suffix
        if suffix.endswith('?') or suffix.endswith('&'):
            suffix = suffix[:-1]

        self.url += suffix
        self.public_url += suffix

        return self


    def get_url(self):
        return self.url


    def get_public_url(self):
        return self.public_url


    def get(self):
        url = self.url
        logger.debug(f'DjangoAPI.get: {url}')

        # In case of get, the instantiation caches queries. Check to see if
        # this  instantiation has already queried and cached. if cached, use
        # the cached version, otherwise query the PM API.
        resp = self._GET_CACHE.get(url)
        if not resp:
            resp = requests.get(url, headers = self._HEADERS)
            self._GET_CACHE[url] = resp
        
        if (code := resp.status_code) not in [200, 404]:
            raise DjangoException(url, resp.json(), code)

        if 'results' in ( json := resp.json() ):
            return json['results']
        return json


    def post(self, data=None):
        url = self.url
        logger.debug(f'DjangoAPI.post: {url}')

        if data:
            resp = requests.post(url, headers = self._HEADERS, json = data)
        else:
            resp = requests.post(url, headers = self._HEADERS)

        out  = resp.json()
        code = resp.status_code

        if code not in range(200, 300):
            raise DjangoException(data=out, code=code, message=self._ERR_MSG)

        self.clear_cache()
        return out


    def patch(self, data):
        url = self.url
        logger.debug(f'DjangoAPI.patch: {url}')
        resp = requests.patch(url, headers = self._HEADERS, json = data )

        out  = resp.json()
        code = resp.status_code

        if code not in range(200, 300):
            raise DjangoException(data=out, code=code, message=self._ERR_MSG)

        self.clear_cache()
        return out


    def delete(self):
        url = self.url
        logger.debug(f'DjangoAPI.patch: {url}')
        resp = requests.delete(url, headers = self._HEADERS)

        code = resp.status_code

        if code not in range(200, 300):
            raise DjangoException(data=resp.json(), code=code, message=self._ERR_MSG)

        self.clear_cache()
        return
