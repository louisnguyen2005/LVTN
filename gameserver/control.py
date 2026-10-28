"""Operator start/finish and consistent SQLite backups."""
import argparse
import json
from pathlib import Path
from .worker import api
from .local import runtime_file


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['start','finish','backup'])
    p.add_argument('--config',type=Path)
    p.add_argument('--server-config',type=Path)
    p.add_argument('--destination',type=Path)
    a=p.parse_args()
    if a.action=='backup':
        if a.destination is None or a.destination.exists():
            p.error('Provide a new --destination file outside the service directory')
        from .server import load_store
        load_store(runtime_file('config.json',a.server_config)).backup(a.destination)
        a.destination.chmod(0o600)
        print('Database backup created; protect this file as an organizer secret.')
    else:
        config=json.loads(runtime_file('operator.json',a.config).read_text(encoding='utf-8-sig'))
        print(json.dumps(api(config,'/api/admin/'+a.action,{},'admin_token')))


if __name__=='__main__':
    main()
