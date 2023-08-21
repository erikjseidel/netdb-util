import logging, yaml, json
from pathlib import Path
from util.web_api import WebAPIException
from copy import deepcopy
from jinja2 import Environment, FileSystemLoader
from util import netdb
from config.repo_yaml import REPO_BASE, REPO_SOURCE

_NETDB_DEV_COLUMN = 'device'

logger = logging.getLogger(__name__)

class RepoUtility:

    def __init__(self):
        path = f'{REPO_BASE}/top.yaml'

        try:
            self.top = yaml.safe_load(Path(path).read_text())
        except FileNotFoundError:
            raise WebAPIException(message=f'Repo top file {path} not found')
        except:
            raise WebAPIException(message=f'Repo top file {path} load error')

        if not isinstance(self.top, dict) or 'base' not in self.top.keys():
            raise WebAPIException(message=f'base not found in top file {path}')

        result, self.devices, message = netdb.get(_NETDB_DEV_COLUMN)
        if not result:
            raise WebAPIException(message=f'netdb device get failure: {message}')


    def _load_templates(self, filenames):
        environment = Environment(loader=FileSystemLoader(REPO_BASE))

        out = []

        for filename in filenames:
            try:
                out.append({
                     'name' : f'{filename}.yaml',
                     'data' : environment.get_template(f'{filename}.yaml'),
                    })
            except Exception as e:
                raise WebAPIException(message=f'Jinja2 load exception for {filename}.yaml: {e.message}')

        return out


    def _render_templates(self, node, templates):
        out = {}

        for template in templates:
            filename = template['name']

            try:
                rendered = template['data'].render(device=self.devices[node], devices=self.devices)
            except Exception as e:
                raise WebAPIException(message=f'Jinja2 rendering exception for {filename}: {e.message}')

            try:
                in_data = yaml.safe_load(rendered)
            except Exception as e:
                raise WebAPIException(message=f'YAML load exception for {filename}: Invalid YAML data')

            out.update(in_data)

        return out


    def generate_column(self, column):
        out = {
                'datasource' : REPO_SOURCE['name'],
                'weight'     : REPO_SOURCE['weight'],
                }

        if not (directory := self.top['base'].get(column)):
            raise WebAPIException(message=f'column {column} not found in base')

        node_sets = self.top.get('node_sets', {})

        common_templates = []
        if filenames := directory.pop('*', None):
            common_templates = self._load_templates(filenames)

        for node_set, nodes in node_sets.items():
            if node_set in directory:
                templates = []

                if set_files := directory.pop(node_set, None):
                    templates = self._load_templates(set_files)

                for node in nodes:
                    node_data = self._render_templates(node, common_templates + templates)

                    out[node] = deepcopy(node_data)

        for node, node_files in directory.items():
            node_templates = self._load_templates(node_files)

            if node not in out.keys():
                out[node] = {}
                node_templates = common_templates + node_templates

            node_data = self._render_templates(node, node_templates)

            out[node].update(deepcopy(node_data))

        return out


    def reload_column(self, column):
        return netdb.reload(column, self.generate_column(column))
