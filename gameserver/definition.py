"""Generate cloud definition files from deployment.json before uploading the source."""
import argparse
import json
from pathlib import Path
import yaml
from .deployment import ROOT,load_deployment,deployment_sha,gateway_maps


def rendered_files(path=None):
    d=load_deployment(path); network=d['network']; images=d['images']
    host=lambda name,image,flavor:{'name':name,'base_box':{'image':image,'mgmt_user':'debian'},'flavor':flavor}
    topology={'name':d['sandbox_name'],'hosts':[host(t['node'],images['team'],images['team_flavor']) for t in d['teams']]+[
        host('server',images['server'],images['server_flavor'])],
        'routers':[host('gateway',images['server'],images['server_flavor'])],
        'wan':{'name':'internet-connection','cidr':'100.100.100.0/24'},
        'networks':[{'name':'lab-lan','cidr':network['cidr'],'accessible_by_user':True}],
        'net_mappings':[{'host':t['node'],'network':'lab-lan','ip':t['ip']} for t in d['teams']]+[{'host':'server','network':'lab-lan','ip':network['server_ip']}],
        'router_mappings':[{'router':'gateway','network':'lab-lan','ip':network['router_ip']}],
        'groups':[{'name':'attackers','nodes':[t['node'] for t in d['teams']]}]}
    attackers={t['node']:t['ip'] for t in d['teams']}
    variables={'lab_deployment_sha256':deployment_sha(path),
        'lab_team_passwords':{t['node']:t['lab_ssh_password'] for t in d['teams']},
        'lab_enforce_owner':False,'lab_hosts':{**attackers,'server':network['server_ip']},
        'lab_attackers':attackers,'lab_teams':d['teams'],'lab_services':d['services'],
        'lab_network':network,'lab_rules':d['rules']}
    content='# NOVA MART Attack–Defense\n\nSSH/console account: `user-access`. Your organizer gives your team password. '+\
        'Per-service web URLs are in `~/lab-addresses.txt` on your VM. Each team receives an isolated instance.\n\n'
    for team in d['teams']:
        content+=f"- {team['id']} identity page: http://{team['ip']}/\n"
        for service in d['services']:
            content+=f"  - {service['name']}: http://{team['ip']}:{service['port']}/\n"
    content+=f"\nNew connections from attacker VMs to the shared server {network['server_ip']} are blocked. The router is {network['router_ip']}.\n\n"+\
        'The service is NOVA MART, an intentionally vulnerable web shop. Challenge paths: SQL injection in product search; CAPTCHA bypass; stored XSS in reviews; CSRF in order sharing; and weak merchant credentials with no effective rate limit. '+\
        'Order private notes hold short-lived flags. The functional checker creates one flag per team/service/tick, checks the current and still-active orders, and awards SLA only when that flow works.\n\n'+\
        'Event schedule: '+str(d['rules']['max_rounds'])+' rounds × '+str(d['rules']['round_seconds']//60)+' minutes; '+\
        str(d['rules']['tick_seconds'])+' seconds/tick; '+str(d['rules']['round_seconds']//d['rules']['tick_seconds'])+\
        ' ticks/round. UP earns '+str(d['rules']['sla_points'])+' SLA point; missed/DOWN/MUMBLE earns zero. A captured active flag earns '+\
        str(d['rules'].get('attack_points',0))+' points and its owner loses '+str(d['rules'].get('defense_penalty',0))+\
        '. Flag lifetime: '+str(d['rules'].get('flag_ttl_ticks',0))+' ticks.\n\n'+\
        'For external access, the organizer runs Configure-Deployment.ps1 after allocation and publishes the generated gateway URLs and scoreboard. The read-only operations monitor has its own token.\n\nEnter `finish-idor-lab` when done.'
    definition={'title':'NOVA MART Attack–Defense CTF','description':'An isolated per-team web shop with tick-based functional SLA checks, short-lived flags, and an attack–defense scoreboard.',
        'prerequisites':['Basic HTTP','Basic Linux commands'],'outcomes':['Operate and patch a web shop','Monitor service SLA and attack–defense scoring'],
        'state':'UNRELEASED','show_stepper_bar':False,'estimated_duration':d['rules']['round_seconds']*d['rules']['max_rounds']//60,
        'variant_sandboxes':False,'levels':[{'title':'CTF service access','level_type':'ACCESS_LEVEL','order':0,
        'estimated_duration':d['rules']['round_seconds']*d['rules']['max_rounds']//60,'minimal_possible_solve_time':None,
        'passkey':'finish-idor-lab','cloud_content':content,'local_content':'Use the assigned CyberRangeCZ cloud Training Instance.'}]}
    acl=f"table inet idor_server_acl {{\n    chain input {{\n        type filter hook input priority -10; policy accept;\n        ip saddr {network['cidr']} ip daddr {network['server_ip']} ct state new drop\n    }}\n}}\n"
    internal={'targets':[{'name':t['id'],'url':f"http://{t['ip']}:{d['services'][0]['port']}/health",
                 'expected_sandbox_suffix':'-'+t['node'],'expected_service':d['services'][0]['id']} for t in d['teams']]}
    example_gateway={'gatewayIp':'127.0.0.1','sshConfig':'<USER_SSH_CONFIG>','sshHost':'man',
                     'allowedClientSubnets':['127.0.0.1/32'],'services':gateway_maps(d)}
    example_targets={'targets':[{'name':t['id'],'url':f"http://127.0.0.1:{d['services'][0]['gateway_base_port']+i}/health",
                     'expected_sandbox_suffix':'-'+t['node'],'expected_service':d['services'][0]['id']} for i,t in enumerate(d['teams'],1)]}
    example_services={'services':[{'id':s['id'],'name':s['name'],'vulnerability_count':s['vulnerability_count'],
                       'check':s['check'],'targets':{t['id']:{'url':f"http://127.0.0.1:{s['gateway_base_port']+i}/health",
                       'expected_sandbox_suffix':'-'+t['node'],'expected_service':s['id']} for i,t in enumerate(d['teams'],1)}} for s in d['services']]}
    dumps=lambda value:json.dumps(value,ensure_ascii=False,indent=2)+'\n'
    return {'topology.yml':yaml.safe_dump(topology,sort_keys=False,allow_unicode=True),
            'provisioning/group_vars/all.yml':'# Generated by python -m gameserver.definition --write; edit deployment.json.\n'+yaml.safe_dump(variables,sort_keys=False,allow_unicode=True),
            'training-definition.json':json.dumps(definition,ensure_ascii=False,indent=2)+'\n',
            'provisioning/files/server-acl.nft':acl,
            'checker/web_targets.json':dumps(internal),
            'checker/web_targets_gateway.example.json':dumps(example_targets),
            'CyberRangeCZ-Windows-Gateway/config.example.json':dumps(example_gateway),
            'gameserver/services.example.json':dumps(example_services)}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');p.add_argument('--deployment',type=Path)
    args=p.parse_args(); files=rendered_files(args.deployment)
    stale=[]
    for relative,content in files.items():
        target=ROOT/relative
        if args.write:
            target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8',newline='\n')
        elif not target.exists() or target.read_text(encoding='utf-8')!=content:stale.append(relative)
    if stale:p.error('Regenerate definition files: '+', '.join(stale))
    print('Cloud definition files generated.' if args.write else 'Cloud definition files match deployment.json.')


if __name__=='__main__':main()
