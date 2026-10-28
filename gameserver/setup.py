"""Create a new event and random tokens without overwriting existing secrets."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from uuid import UUID

from .store import validate_config


AD_RULES = {'round_seconds':60,'max_rounds':60,'flag_ttl_rounds':3,
                 'sla_points':10,'attack_points':100,'defense_penalty':100}
DEFAULT_RULES = {'mode':'sla','round_seconds':1800,'max_rounds':2,'tick_seconds':120,'sla_points':1}


def secure_directory(root):
    root.chmod(0o700)
    if os.name == 'nt':
        identity=subprocess.check_output(['whoami','/user','/fo','csv','/nh'],text=True)
        sid=re.search(r'S-1-5-(?:\d+-)*\d+',identity).group(0)
        subprocess.run(['icacls',str(root),'/reset'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['icacls',str(root),'/inheritance:r','/grant:r',
                        '*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],
                       check=True,stdout=subprocess.DEVNULL)


def write_private(path,data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    # Exclusive creation prevents accidentally rotating a running event's tokens.
    with path.open('x',encoding='utf-8') as stream:
        json.dump(data,stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    path.chmod(0o600)


def initialize(directory,event_id,sandbox_id,targets,backend_url='http://127.0.0.1:9000',rules=None,public_url=None,services=None,demo=False):
    root=Path(directory)
    if root.exists() and any(root.iterdir()):
        raise ValueError('Choose an empty runtime directory; existing data is never overwritten')
    UUID(sandbox_id)
    cfg={'event_id':event_id,'sandbox_id':sandbox_id,'database':'competition.sqlite',
         'admin_token':secrets.token_urlsafe(32),'checker_token':secrets.token_urlsafe(32),
         'rules':dict(rules or DEFAULT_RULES),'teams':[
             {'id':t['team'],'url':t['url'],'expected_sandbox':t['expected_sandbox'],'token':secrets.token_urlsafe(32)}
             for t in targets]}
    if cfg['rules'].get('mode')=='sla':
        cfg['services']=services or []
        cfg['demo']=demo
    validate_config(cfg)
    root.mkdir(parents=True,exist_ok=True)
    secure_directory(root)
    write_private(root/'config.json',cfg)
    preflight_targets=targets
    if cfg['rules'].get('mode')=='sla':
        preflight_targets=[{'team':team,'service_id':s['id'],'check_level':s.get('check','health'),**t}
                           for s in cfg['services'][:1] for team,t in s['targets'].items()]
    write_private(root/'worker.json',{'backend_url':backend_url,'checker_token':cfg['checker_token'],
                                    'mode':cfg['rules'].get('mode','attack_defense'),'preflight_targets':preflight_targets})
    write_private(root/'operator.json',{'backend_url':backend_url,'admin_token':cfg['admin_token']})
    for team in cfg['teams']:
        write_private(root/'teams'/f"{team['id']}.json",{'backend_url':public_url or backend_url,'team':team['id'],'token':team['token']})
    return cfg


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path('gameserver/runtime-sla'))
    parser.add_argument('--gateway-config',type=Path,default=Path('CyberRangeCZ-Windows-Gateway/config.json'))
    parser.add_argument('--targets',type=Path,default=Path('checker/web_targets_gateway.json'))
    parser.add_argument('--event-id',default='idor-training-001')
    parser.add_argument('--backend-url',default='http://127.0.0.1:9000')
    parser.add_argument('--public-url',help='Contestant-facing scoreboard origin; organizer clients can keep using loopback')
    parser.add_argument('--services-config',type=Path,help='JSON with one service and per-team targets for each round')
    for key,value in DEFAULT_RULES.items():
        if key!='mode':
            parser.add_argument('--'+key.replace('_','-'),type=int,default=value)
    args=parser.parse_args()
    gateway=json.loads(args.gateway_config.read_text(encoding='utf-8-sig'))
    matched=re.search(r'sandbox-id-([0-9a-fA-F-]{36})-user-config$',gateway['sshConfig'])
    if not matched:
        parser.error('sshConfig must identify the current sandbox')
    sandbox=str(UUID(matched.group(1)))
    targets=json.loads(args.targets.read_text(encoding='utf-8-sig'))['targets']
    confirmed={int(s['gatewayPort']):(s['sandboxIp'],int(s['sandboxPort'])) for s in gateway['services']}
    from urllib.parse import urlsplit
    for t in targets:
        url=urlsplit(t['url'])
        if url.hostname!=gateway['gatewayIp'] or url.port not in confirmed or url.path!='/health':
            parser.error('Target does not match gateway configuration')
        suffix=t['expected_sandbox_suffix']
        if not re.fullmatch(r'-[a-z][a-z0-9_-]{0,31}',suffix) or (t.get('sandbox_ip') and confirmed[url.port][0]!=t['sandbox_ip']):
            parser.error('Team URL and gateway backend mapping do not agree')
    converted=[{'team':t['name'],'url':t['url'].removesuffix('/health'),
                'expected_sandbox':sandbox+t['expected_sandbox_suffix']} for t in targets]
    try:
        rules={key:getattr(args,key) for key in DEFAULT_RULES if key!='mode'}
        rules['mode']='sla'
        if args.services_config is None:
            parser.error('Provide --services-config for BOTH services; see gameserver/services.example.json')
        services=json.loads(args.services_config.read_text(encoding='utf-8-sig'))['services']
        for service in services:
            for target in service['targets'].values():
                suffix=target.pop('expected_sandbox_suffix',None)
                if suffix:
                    target['expected_sandbox']=sandbox+suffix
        initialize(args.directory,args.event_id,sandbox,converted,args.backend_url,rules,args.public_url,services=services)
    except (OSError,ValueError) as exc:
        parser.error(str(exc))
    print(f'Created private event configuration in {args.directory}. Review rules before starting. No tokens printed.')


if __name__=='__main__':
    main()
