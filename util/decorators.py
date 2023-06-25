import logging

from flask import Response, json
from functools import wraps
from .django_api import DjangoException
from modules.pm import PMException
from modules.netbox import NetboxException

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

            if method not in methods:
                ret = { 'result': False, 'error': True, 'comment': 'Invalid method' }
                status = 404

            else:
                try:
                    result, out, comment = func(*args, **kwargs)

                    assert isinstance(result, bool)
                    assert (out == None) or isinstance(out, dict), isinstance(comment, str)

                    ret = { 'result': result, 'error': False, 'comment': comment }

                    if out: ret.update({ 'out': out })

                except DjangoException as e:
                    logger.error(f'exception: {e.message}', exc_info=e)
                    ret = { 'result': False, 'error': True, 'comment': e.message }

                except (PMException, NetboxException) as e:
                    ret = { 'result': False, 'error': False, 'comment': e.message }

            return Response(response = json.dumps(ret), status = 200, mimetype = 'application/json')
        return wrapped

    # allow decorator to be used without calling it (e.g. when no paramators required).
    if callable(methods):
        f = methods
        methods = ['GET']
        return inner_decorator(f)
    else:
        return inner_decorator
