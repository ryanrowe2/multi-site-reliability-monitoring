#!/usr/bin/env python3
"""Fail-closed YAML credential gate. Requires pinned PyYAML (see requirements-security.txt).
Uses safe node construction, rejects duplicate/non-string mapping keys and custom tags.
Output intentionally contains no scanned values or secrets.
"""
import re
import sys
import yaml

class StrictSafeLoader(yaml.SafeLoader):
    # YAML 1.2 reserves booleans for true/false; GitHub Actions uses `on` as
    # an ordinary key, not the YAML 1.1 boolean `True`.
    yaml_implicit_resolvers = {
        key: [item for item in resolvers if item[0] != 'tag:yaml.org,2002:bool']
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise ValueError('expected mapping')
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in seen:
                raise ValueError('duplicate or non-string YAML key')
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def sensitive(key):
    name = re.sub(r'[^a-z0-9]', '', key.lower())
    aliases = {'dbpass', 'dbpasswd', 'dbpassword', 'dbpwd', 'mysqlpwd', 'pgpassword',
               'dburi', 'databaseurl', 'databaseuri', 'postgresurl',
               'connectionstring', 'authorization', 'sqlpass', 'sqlauth',
               'serviceauth', 'awssecretaccesskey', 'apikey', 'authkey'}
    return name in aliases or any(name.endswith(suffix) for suffix in
        ('password', 'passwd', 'passphrase', 'secret', 'token', 'credential',
         'credentials', 'privatekey', 'apikey', 'authkey', 'accesskey', 'dbpass', 'pwd'))


def literal(value):
    if value is None or value is False or value == '':
        return False
    if isinstance(value, str) and value.strip().lower() in ('null', '~', '<redacted>', 'changeme', 'placeholder'):
        return False
    if isinstance(value, str) and re.fullmatch(r'\$\{(?:\{.*\}|[^}]+)\}', value.strip()):
        return False
    return True


def embedded_credentials(value):
    if not isinstance(value, str):
        return False
    return bool(re.search(r'\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@', value, re.I))


def suspicious(node):
    if isinstance(node, dict):
        # Mapping ordering is irrelevant for environment name/value sequences.
        if isinstance(node.get('name'), str) and sensitive(node['name']) and literal(node.get('value')):
            return True
        for key, value in node.items():
            if sensitive(key) and literal(value):
                return True
            if suspicious(value):
                return True
    elif isinstance(node, list):
        return any(suspicious(item) for item in node)
    elif isinstance(node, str):
        if embedded_credentials(node):
            return True
        line = node.strip().strip('"\'')
        match = re.match(r'^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$', line, re.I)
        if match and sensitive(match[1]) and literal(match[2]):
            return True
    return False


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError('expected one filename')
        # A safe bounded release parser: reject non-UTF-8 and huge YAML inputs.
        with open(sys.argv[1], 'rb') as fd:
            content = fd.read(524289)
        if len(content) > 524288:
            raise ValueError('YAML exceeds conservative scan limit')
        documents = list(yaml.load_all(content.decode('utf-8'), Loader=StrictSafeLoader))
        if not documents or any(suspicious(doc) for doc in documents):
            return 1
        return 0
    except Exception:
        return 2

if __name__ == '__main__':
    sys.exit(main())
