"""Validate generated cloud files and allocation bootstrap without a live pool."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
from unittest.mock import patch,MagicMock
import yaml
from jinja2 import Environment,StrictUndefined

from gameserver.configure import prepare,routed_ip
from gameserver.deployment import ROOT,load_deployment,gateway_maps,service_targets
from gameserver.definition import rendered_files
from gameserver.package import source_files
from gameserver.server import load_store


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.data=load_deployment()
        # Stable test scenario independent of the operator's editable manifest.
        self.data['network']={'cidr':'10.80.0.0/24','router_ip':'10.80.0.1','server_ip':'10.80.0.20'}
        self.data['rules']={'mode':'sla','round_seconds':1800,'max_rounds':2,'tick_seconds':120,'sla_points':1}
        self.data['teams']=[{'id':f'team{i:02d}','node':f'attacker{i}','ip':f'10.80.0.{10+i}',
                            'lab_ssh_password':f'test-password-{i:02d}'} for i in range(1,5)]
        self.data['services']=[{'id':f'service{i:02d}','name':f'Service {i}','port':8079+i,
            'gateway_base_port':8000+i*10,'vulnerability_count':5,'check':'workflow','implementation':'servicedesk-demo'} for i in (1,2)]
        self.manifest=self.root/'deployment.json'
        self.manifest.write_text(json.dumps(self.data),encoding='utf-8')
        self.sandbox=str(uuid4())
        self.ssh=self.root/f'pool-id-7-sandbox-id-{self.sandbox}-user-config'
        self.ssh.write_text('Host man\n HostName 192.0.2.10\n User user\n')

    def test_generated_files_are_current_and_two_round_services_are_provisioned(self):
        for relative,content in rendered_files().items():
            self.assertEqual((ROOT/relative).read_text(encoding='utf-8'),content,relative)
        variables=yaml.safe_load(rendered_files()['provisioning/group_vars/all.yml'])
        current=load_deployment()
        self.assertEqual(variables['lab_services'],current['services'])
        self.assertEqual(len(gateway_maps(current)),len(current['teams'])*len(current['services'])+1)
        self.assertNotIn('pool-id-',rendered_files()['training-definition.json'])

    def test_manifest_changes_regenerate_nodes_addresses_ports_and_rules(self):
        d=self.data
        d['teams']=d['teams'][:2]
        d['network']={'cidr':'192.168.77.0/24','router_ip':'192.168.77.1','server_ip':'192.168.77.20'}
        for i,t in enumerate(d['teams'],1):t.update(id=f'red{i}',node=f'node{i}',ip=f'192.168.77.{10+i}')
        d['services'][0].update(port=9100,gateway_base_port=8110)
        d['services'][1].update(port=9101,gateway_base_port=8210)
        d['rules'].update(round_seconds=900,tick_seconds=60)
        self.manifest.write_text(json.dumps(d),encoding='utf-8')
        files=rendered_files(self.manifest)
        topology=yaml.safe_load(files['topology.yml'])
        self.assertEqual([h['name'] for h in topology['hosts']],['node1','node2','server'])
        self.assertIn('192.168.77.0/24',files['provisioning/files/server-acl.nft'])
        targets=service_targets(load_deployment(self.manifest),'127.0.0.1',self.sandbox)
        self.assertEqual(targets[1]['targets']['red2']['url'],'http://127.0.0.1:8212/health')
        self.assertEqual(targets[1]['targets']['red2']['expected_sandbox'],self.sandbox+'-node2')

    def test_bootstrap_creates_ready_database_and_generated_transport(self):
        report=prepare(self.root,self.manifest,self.ssh,'auto','test-event')
        runtime=Path(report['runtime']);store=load_store(runtime/'config.json')
        self.assertEqual(store.public()['phase'],'ready')
        self.assertEqual(store.public()['total_ticks'],30)
        gateway=json.loads((self.root/'CyberRangeCZ-Windows-Gateway/config.json').read_text())
        self.assertEqual(gateway['gatewayIp'],'127.0.0.1')
        self.assertEqual(len(gateway['services']),9)
        selected=json.loads((self.root/'gameserver/local.json').read_text())
        self.assertEqual(selected['active_runtime'],'gameserver/runtime-sla-test-event')
        alias=Path(report['team_ssh_config']).read_text()
        self.assertIn('Host team02',alias);self.assertIn('PubkeyAuthentication no',alias)
        self.assertNotIn(self.data['teams'][0]['lab_ssh_password'],alias)
        with self.assertRaises(ValueError):prepare(self.root,self.manifest,self.ssh,'auto','test-event')
        store.start()
        with self.assertRaises(ValueError):prepare(self.root,self.manifest,self.ssh,'auto','another-event')
        self.assertEqual(json.loads((self.root/'gameserver/local.json').read_text()),selected)

    def test_dry_run_writes_nothing_and_lan_requires_explicit_scope(self):
        before={p.relative_to(self.root) for p in self.root.rglob('*')}
        result=prepare(self.root,self.manifest,self.ssh,'auto','dry',dry_run=True)
        self.assertEqual(result['forward_count'],9)
        self.assertEqual(before,{p.relative_to(self.root) for p in self.root.rglob('*')})
        with self.assertRaises(ValueError):prepare(self.root,self.manifest,self.ssh,'192.0.2.5','lan',access='lan')
        result=prepare(self.root,self.manifest,self.ssh,'192.0.2.5','lan',access='lan',client_cidrs=['192.0.2.0/24'],dry_run=True)
        self.assertEqual(result['gateway_ip'],'192.0.2.5')

    def test_auto_gateway_handles_openssh_bracketed_ipv4_proxy(self):
        process=MagicMock(stdout='hostname 192.168.5.10\nproxyjump allocation-user@[10.32.8.175]\n')
        route=MagicMock();route.__enter__.return_value=route;route.getsockname.return_value=('192.0.2.5',50000)
        with patch('gameserver.configure.subprocess.run',return_value=process),patch('gameserver.configure.socket.socket',return_value=route):
            self.assertEqual(routed_ip(self.ssh),'192.0.2.5')
            route.connect.assert_called_once_with(('10.32.8.175',22))

    def test_duplicate_port_network_or_service_injection_is_rejected(self):
        changes=[lambda d:d['services'][1].update(port=8080),
                 lambda d:d['services'][1].update(gateway_base_port=8010),
                 lambda d:d['services'][1].update(id='../other'),
                 lambda d:d['teams'][1].update(ip=d['teams'][0]['ip']),
                 lambda d:d['rules'].update(tick_seconds=121)]
        for change in changes:
            d=copy.deepcopy(self.data);change(d);self.manifest.write_text(json.dumps(d))
            with self.assertRaises(ValueError):load_deployment(self.manifest)

    def test_templates_render_distinct_service_configs_and_fixed_sudo_commands(self):
        env=Environment(undefined=StrictUndefined)
        env.filters['bool']=bool
        env.filters['to_nice_json']=lambda value:json.dumps(value)
        context={'lab_services':self.data['services'],'lab_teams':self.data['teams'],
                 'lab_hosts':{t['node']:t['ip'] for t in self.data['teams']},'inventory_hostname':'attacker1',
                 'global_sandbox_id':self.sandbox,'lab_enforce_owner':False,
                 'lab_service_passwords':{'service01':'private-a','service02':'private-b'},
                 'lab_network':self.data['network'],'lab_rules':self.data['rules']}
        sudo=env.from_string((ROOT/'provisioning/templates/team-restarts.j2').read_text()).render(**context)
        self.assertIn('restart servicedesk@service01.service',sudo)
        self.assertIn('restart servicedesk@service02.service',sudo)
        self.assertNotIn('NOPASSWD: ALL',sudo)
        tasks=yaml.safe_load((ROOT/'provisioning/service-instance.yml').read_text())
        config=next(t['ansible.builtin.copy']['content'] for t in tasks if t.get('name','').startswith('Store this service'))
        parsed=[json.loads(env.from_string(config).render(**context,lab_service=s)) for s in self.data['services']]
        self.assertNotEqual(parsed[0]['database'],parsed[1]['database'])
        self.assertEqual([c['listen_port'] for c in parsed],[8080,8081])
        addresses=env.from_string((ROOT/'provisioning/templates/lab-addresses.j2').read_text()).render(**context)
        self.assertIn('service01.json',addresses);self.assertIn('service02.json',addresses)

    def test_package_selection_excludes_all_runtime_and_environment_files(self):
        examples=['app/portal.py','gameserver/demo.py','gameserver/schema.sql','deployment.json','provisioning/playbook.yml',
                  'gameserver/runtime-secret/config.json','gameserver/local.json','gameserver/services.json',
                  'CyberRangeCZ-Windows-Gateway/config.json','checker/credentials.json',
                  'checker/results/latest.json','.git/config']
        for relative in examples:
            p=self.root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('{}')
        selected={p.as_posix() for p,_ in source_files(self.root)}
        self.assertTrue({'app/portal.py','gameserver/demo.py','deployment.json','provisioning/playbook.yml'}<=selected)
        self.assertIn('gameserver/schema.sql',selected)
        self.assertFalse(any('runtime' in p or 'credentials.json' in p or p=='gameserver/local.json' or p=='.git/config' for p in selected))


if __name__=='__main__':unittest.main()
