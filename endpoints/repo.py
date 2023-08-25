import logging
from util.decorators import restful_method
from modules.repo import RepoUtility

# Public symbols
__all__ = [
        'generate_column',
        'reload_column',
        ]

logger = logging.getLogger(__name__)

@restful_method
def generate_column(method, data, params):
    column = params.get('column')

    data = RepoUtility().generate_column(column)

    msg = f'Column not found'
    if data:
        msg = 'Column generated from repo_yaml'

    return bool(data), data, msg


@restful_method(methods=['POST'])
def reload_column(method, data, params):
    column = params.get('column')

    data = RepoUtility().reload_column(column)

    msg = f'Column not found'
    if data:
        msg = 'Column generated from repo_yaml'

    return bool(data), data, f'{column}: column reloaded'