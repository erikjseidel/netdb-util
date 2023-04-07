from flask import Response, json
from functools import wraps

def netdb_consumer(func):
    """
    Converts netdb three tuple dict output into internal three tuple ret format.

    netdb is expected to return a dict of the following format:
            {
            'result' : bool,
            'error'  : bool,
            'out'    : dict,
            'comment': str,
            }

    This will be converted into three vars and returned:
            result:  (bool) whether or not result was given
            out:     (dict) dictionary containing netdb data
            comment: (str)  a brief message describing operation / result

    If 'out' is not found in netdb dict result, returned 'out' will be set to None.
    """
    def decorator(*args, **kwargs):
        response = func(*args, **kwargs)

        try:
            ret = response.json()
        except Exception:
            return False, None, 'Invalid netdb response'

        if (not ret['result']) or ret['error']:
            result = False
        else:
            result = True

        if 'out' in ret:
            out = ret['out']
        else:
            out = None

        comment = ret['comment']

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
                result, out, comment = func(*args, **kwargs)

                assert isinstance(result, bool)
                assert (out == None) or isinstance(out, dict), isinstance(comment, str)

                ret = { 'result': result, 'error': False, 'comment': comment }

                if out: ret.update({ 'out': out })

                status = 200

            return Response(response = json.dumps(ret), status = status, mimetype = 'application/json')
        return wrapped

    # allow decorator to be used without calling it (e.g. when no paramators required).
    if callable(methods):
        f = methods
        methods = ['GET']
        return inner_decorator(f)
    else:
        return inner_decorator
