import logging
from flask import Response, json
from functools import wraps
from .django_api import DjangoException
from modules.pm import PMException
from modules.netbox import NetboxException
from modules.ripe import RipeStatException
from util.web_api import WebAPIException

logger = logging.getLogger(__name__)

def util_internal(func):
    """
    Checks / enforces regular returns for util internal methods. Wrapped
    functions must return three vars:

    result:  (bool) whether or not result was given
    out:     (dict) dictionary containing netdb data
    comment: (str)  a brief message describing operation / result

    """
    def decorator(*args, **kwargs):
        result, out, comment = func(*args, **kwargs)

        assert isinstance(result, bool)
        assert (out == None) or isinstance(out, (list, dict)), isinstance(comment, str)

        return result, out, comment
    return decorator


def restful_method(methods=['GET']):
    """
    Enforces three tuple return and converts it to salt style output wrapped in a
    Flask response object. Will return a 404 response if caller's request method is
    not in the list of allowed methods (default is 'GET').

    Wrapped functions must return three vars:
    result:  (bool) whether or not result was given
    out:     (dict) dictionary containing netdb data
    comment: (str)  a brief message describing operation / result
    This becomes: {
            'result' : bool,
            'error'  : bool,
            'out'    : dict,
            'comment': str,
            }

    If incoming 'out' is None, 'out' will not be returned in the resulting dict.
    """
    def inner_decorator(func):
        def wrapped(*args, **kwargs):

            method = kwargs.get('method')

            status = 200

            if method not in methods:
                ret = { 'result': False, 'error': True, 'comment': 'Invalid method' }
                status = 404

            else:
                ret = { 
                        'result'  : result, 
                        'error'   : False,
                        'comment' : comment,
                        }

                try:
                    result, out, comment = func(*args, **kwargs)

                    assert isinstance(result, bool)
                    assert (out == None) or isinstance(out, dict), isinstance(comment, str)

                except Exception as e:
                    if not issubclass(e, WebAPIException):
                        raise e

                    ret['result'] = False

                    status = e.code

                    if status in range(500, 600):
                        logger.error(f'Exception occured: {e.message}', exc_info=e)
                        ret['error'] = True

                    out = e.data

                finally:
                    if out:
                        ret['out'] = out

            return Response(response=json.dumps(ret), status=status, mimetype='application/json')
        return wrapped

    # allow decorator to be used without calling it (e.g. when no paramators required).
    if callable(methods):
        f = methods
        methods = ['GET']
        return inner_decorator(f)
    else:
        return inner_decorator
