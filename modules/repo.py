from pathlib import Path
import yaml, json
from util.web_api import WebAPIException
from copy import deepcopy

from pprint import pprint

class RepoUtility:
    REPO_BASE='/srv/repo_yaml'

    def __init__(self):
        path = f'{self.REPO_BASE}/top.yaml'

        try:
            self.top = yaml.safe_load(Path(path).read_text())
        except FileNotFoundError:
            raise WebAPIException(message=f'Repo top file {path} not found')
        except:
            raise WebAPIException(message=f'Repo top file {path} load error')

        if not isinstance(self.top, dict) or 'base' not in self.top.keys():
            raise WebAPIException(message=f'base not found in top file {path}')


    def generate_column(self, column):
        out = {}

        if not (directory := self.top['base'].get(column)):
            raise WebAPIException(message=f'column {column} not found in base')

        node_sets = self.top.get('node_sets', {})

        common = {}
        if filenames := directory.pop('*', None):
            for filename in filenames:
                path = f'{self.REPO_BASE}/{filename}.yaml'
                try:
                    in_data = yaml.safe_load(Path(path).read_text())
                except FileNotFoundError:
                    in_data = {}

                common.update(in_data)

        for node_set, nodes in node_sets.items():
            set_data = {}

            if set_files := directory.pop(node_set, None):
                for filename in set_files:
                    path = f'{self.REPO_BASE}/{filename}.yaml'
                    print(path)
                    try:
                        in_data = yaml.safe_load(Path(path).read_text())
                    except FileNotFoundError:
                        in_data = {}

                    set_data.update(in_data)

            if set_data:
                for node in nodes:
                    out[node] = deepcopy(common)
                    out[node].update(deepcopy(set_data))

                 #   print('#####################' + node + '#################')
                 #   print(yaml.dump(out))


        for node, node_files in directory.items():
            node_data = {}
            for filename in node_files:
                path = f'{self.REPO_BASE}/{filename}.yaml'
                try:
                    in_data = yaml.safe_load(Path(path).read_text())
                except FileNotFoundError:
                    in_data = {}

                node_data.update(in_data)

            if node_data:
                if node not in out.keys():
                    out[node] = deepcopy(common)

                out[node].update(deepcopy(node_data))

        return out
