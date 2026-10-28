"""Create environment-specific gateway/checker files after an allocation is assigned."""
import argparse
from datetime import datetime,timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
from uuid import UUID,uuid4

from .deployment import ROOT,load_deployment,gateway_maps,service_targets
from .setup import initialize,secure_directory


def allocation_id(path):
    path=Path(path).expanduser().resolve()
    if not path.is_file():raise ValueError('Extract the current user SSH config/key into .ssh first')
    match=re.fullmatch(r'pool-id-([0-9]+)-sandbox-id-([0-9a-fA-F-]{36})-user-config',path.name)
    if not match:raise ValueError('Select the downloaded allocation user-config, not management-config')
    return path,match.group(1),str(UUID(match.group(2)))


def routed_ip(config,alias='man'):
    result=subprocess.run(['ssh','-G','-F',str(config),alias],check=True,capture_output=True,text=True)
    details=dict(line.split(' ',1) for line in result.stdout.splitlines() if ' ' in line)
    proxy=details.get('proxyjump','none').split(',')[0]
    from urllib.parse import urlsplit
    target=urlsplit('ssh://'+proxy).hostname if proxy!='none' else details['hostname']
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
        route.connect((socket.gethostbyname(target),22))
        return route.getsockname()[0]


def atomic_json(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid4().hex+'.tmp')
    try:
        temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        temporary.replace(path)
    finally:
        if temporary.exists():temporary.unlink()


def prepare(root,manifest,ssh_config,gateway_ip,event_id,access='local',client_cidrs=None,backend_port=9000,dry_run=False):
    root=Path(root).resolve();data=load_deployment(manifest)
    ssh_path,pool,sandbox=allocation_id(ssh_config)
    if access not in ('local','lan'):raise ValueError('Use local or lan access')
    bind='127.0.0.1' if access=='local' else gateway_ip
    if bind=='auto':bind=routed_ip(ssh_path)
    bind=str(ipaddress.IPv4Address(bind))
    cidrs=['127.0.0.1/32'] if access=='local' else list(client_cidrs or [])
    if access=='lan' and not cidrs:raise ValueError('LAN mode requires --client-cidr; local mode needs no LAN firewall rule')
    for c in cidrs:ipaddress.IPv4Network(c,strict=False)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',event_id):raise ValueError('Invalid event ID')
    if not 1024<=backend_port<=65535:raise ValueError('Invalid backend port')
    mappings=gateway_maps(data)
    if backend_port in {m['gatewayPort'] for m in mappings}:raise ValueError('Backend port overlaps a gateway port')
    runtime=root/'gameserver'/('runtime-sla-'+event_id)
    if runtime.exists() and any(runtime.iterdir()):raise ValueError('Event directory exists; choose a new event ID')
    pointer=root/'gameserver/local.json'
    if pointer.exists():
        previous=json.loads(pointer.read_text(encoding='utf-8-sig'))
        previous_runtime=Path(previous['active_runtime'])
        if not previous_runtime.is_absolute():previous_runtime=root/previous_runtime
        previous_config=previous_runtime/'config.json'
        if previous_config.exists():
            from .server import load_store
            if load_store(previous_config).public()['phase']=='running':
                raise ValueError('Finish the current event before changing the active allocation/configuration')
    services=service_targets(data,bind,sandbox)
    teams=[{'team':t['id'],'url':services[0]['targets'][t['id']]['url'].removesuffix('/health'),
            'expected_sandbox':sandbox+'-'+t['node']} for t in data['teams']]
    gateway={'gatewayIp':bind,'sshConfig':str(ssh_path),'sshHost':'man','allowedClientSubnets':cidrs,
             'maxRestartAttempts':5,'restartDelaySeconds':5,'healthCheckIntervalSeconds':15,'startupTimeoutSeconds':20,
             'services':mappings}
    health={'targets':[{'name':t['id'],'url':services[0]['targets'][t['id']]['url'],
             'expected_sandbox_suffix':'-'+t['node'],'expected_service':services[0]['id'],'sandbox_ip':t['ip']} for t in data['teams']]}
    report={'event_id':event_id,'pool_id':pool,'sandbox_id':sandbox,'gateway_ip':bind,
            'access':access,'runtime':str(runtime),'backend_port':backend_port,'forward_count':len(mappings),
            'rules':data['rules'],'service_ids':[s['id'] for s in services]}
    if dry_run:return report
    backend_url=f'http://127.0.0.1:{backend_port}'
    # Bind all interfaces in LAN mode so organizer clients can keep using loopback.
    backend_bind='0.0.0.0' if access=='lan' else '127.0.0.1'
    initialize(runtime,event_id,sandbox,teams,backend_url,data['rules'],
               f'http://{bind}:{backend_port}',services=services)
    outputs={'CyberRangeCZ-Windows-Gateway/config.json':gateway,'checker/web_targets_gateway.json':health,
             'gameserver/services.json':{'services':services}}
    backup=root/'gameserver'/('runtime-config-backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex[:6])
    previous_files=[p for p in (*outputs,'gameserver/local.json') if (root/p).exists()]
    if previous_files:
        backup.mkdir(parents=True);secure_directory(backup)
        for relative in previous_files:
            target=backup/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/relative,target)
    for relative,value in outputs.items():atomic_json(root/relative,value)
    # Only the backend creates/opens the central SQLite database.
    from .server import load_store
    store=load_store(runtime/'config.json')
    if store.public()['phase']!='ready':raise ValueError('New event must be ready, not started')
    atomic_json(pointer,{'active_runtime':str(runtime.relative_to(root)),
                        'backend_bind':backend_bind,'backend_port':backend_port,'gateway_ip':bind,
                        'pool_id':pool,'sandbox_id':sandbox,'manifest':str(Path(manifest).resolve())})
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--deployment',type=Path,default=ROOT/'deployment.json')
    p.add_argument('--ssh-config',type=Path,required=True)
    p.add_argument('--gateway-ip',default='auto')
    p.add_argument('--event-id',default='sla-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))
    p.add_argument('--access',choices=['local','lan'],default='local')
    p.add_argument('--client-cidr',action='append',default=[])
    p.add_argument('--backend-port',type=int,default=9000)
    p.add_argument('--dry-run',action='store_true')
    args=p.parse_args()
    try:
        report=prepare(ROOT,args.deployment,args.ssh_config,args.gateway_ip,args.event_id,
                       args.access,args.client_cidr,args.backend_port,args.dry_run)
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:p.error(str(exc))
    print(json.dumps(report,ensure_ascii=False,indent=2))
    print('Dry run; no files written.' if args.dry_run else 'SQLite initialized in READY state. Verify gateway and preflight before starting the event.')


if __name__=='__main__':main()
