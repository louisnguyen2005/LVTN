"""Validated deployment manifest shared by definition generation and local bootstrap."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]


def load_deployment(path=None):
    path=Path(path or ROOT/'deployment.json')
    data=json.loads(path.read_text(encoding='utf-8-sig'))
    if data.get('schema_version')!=1:
        raise ValueError('Unsupported deployment schema')
    network=ipaddress.ip_network(data['network']['cidr'],strict=True)
    if network.version!=4:
        raise ValueError('Use an IPv4 sandbox LAN')
    addresses=[]
    for key in ('router_ip','server_ip'):
        addresses.append(ipaddress.ip_address(data['network'][key]))
    ids,nodes,passwords=set(),set(),set()
    teams=data['teams']
    if not 2<=len(teams)<=64:
        raise ValueError('Configure 2-64 teams')
    for team in teams:
        for field,seen in (('id',ids),('node',nodes)):
            value=team[field]
            if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',value) or value in seen:
                raise ValueError('Duplicate or invalid team '+field)
            seen.add(value)
        if team['node'] in ('server','gateway'):
            raise ValueError('Team node conflicts with infrastructure')
        password=team['lab_ssh_password']
        if not isinstance(password,str) or len(password)<12 or password in passwords:
            raise ValueError('Use distinct lab SSH passwords of at least 12 characters')
        passwords.add(password)
        addresses.append(ipaddress.ip_address(team['ip']))
    if len(set(addresses))!=len(addresses) or any(a not in network or a in (network.network_address,network.broadcast_address) for a in addresses):
        raise ValueError('Sandbox IPs must be distinct usable addresses inside its LAN')
    rules=data['rules']
    for key in ('round_seconds','max_rounds','tick_seconds','sla_points'):
        if type(rules[key]) is not int or rules[key]<(0 if key=='sla_points' else 1):
            raise ValueError('Invalid schedule '+key)
    if rules.get('mode')!='sla' or rules['round_seconds']%rules['tick_seconds'] or rules['max_rounds']!=len(data['services']):
        raise ValueError('Use SLA mode, whole ticks and one service per round')
    services,ports,forwards=set(),set(),{8080}
    for service in data['services']:
        ident=service['id']
        if not isinstance(ident,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',ident) or ident in services:
            raise ValueError('Invalid or duplicate service ID')
        services.add(ident)
        port=service['port']
        if type(port) is not int or not 1024<=port<=65535 or port in ports:
            raise ValueError('Use distinct unprivileged service ports')
        ports.add(port)
        if service.get('implementation')!='servicedesk-demo' or service.get('check') not in ('health','workflow'):
            raise ValueError('This provisioning version supports servicedesk-demo with health or workflow checks')
        if type(service['vulnerability_count']) is not int or service['vulnerability_count']<1 or not service.get('name'):
            raise ValueError('Service metadata is incomplete')
        base=service['gateway_base_port']
        if type(base) is not int:
            raise ValueError('gateway_base_port must be an integer')
        for i in range(1,len(teams)+1):
            target=base+i
            if not 1024<=target<=65535 or target in forwards:
                raise ValueError('Gateway ports overlap or are invalid')
            forwards.add(target)
    return data


def deployment_sha(path=None):
    return hashlib.sha256(Path(path or ROOT/'deployment.json').read_text(encoding='utf-8-sig').encode('utf-8')).hexdigest()


def gateway_maps(data):
    mappings=[{'name':'Shared organizer ServiceDesk','protocol':'http','gatewayPort':8080,
               'sandboxIp':data['network']['server_ip'],'sandboxPort':80}]
    for service in data['services']:
        for i,team in enumerate(data['teams'],1):
            mappings.append({'name':service['id']+' '+team['id'],'protocol':'http',
                             'gatewayPort':service['gateway_base_port']+i,'sandboxIp':team['ip'],'sandboxPort':service['port']})
    return mappings


def service_targets(data,gateway_ip,sandbox_id):
    origin='http://'+str(ipaddress.IPv4Address(gateway_ip))
    return [{'id':s['id'],'name':s['name'],'vulnerability_count':s['vulnerability_count'],
             'check':s['check'],'targets':{t['id']:{
                 'url':f"{origin}:{s['gateway_base_port']+i}/health",
                 'expected_sandbox':sandbox_id+'-'+t['node'],'expected_service':s['id']}
                 for i,t in enumerate(data['teams'],1)}} for s in data['services']]
