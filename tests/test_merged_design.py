import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / 'CyberRangeCZ-Windows-Gateway'


def load_yaml(relative):
    return yaml.safe_load((ROOT / relative).read_text(encoding='utf-8'))


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def play(playbook, name_part):
    matches = [p for p in playbook if name_part in p['name']]
    assert len(matches) == 1, f'expected one play containing {name_part!r}, found {len(matches)}'
    return matches[0]


def task(tasks, name_part):
    matches = [t for t in tasks if name_part in t.get('name', '')]
    assert len(matches) == 1, f'expected one task containing {name_part!r}, found {len(matches)}'
    return matches[0]


class PasswordOnlySshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vars = load_yaml('provisioning/group_vars/all.yml')
        cls.playbook = load_yaml('provisioning/playbook.yml')
        cls.playbook_text = (ROOT / 'provisioning/playbook.yml').read_text(encoding='utf-8')
        cls.attackers = play(cls.playbook, 'Give each attacker')

    def test_every_attacker_has_its_own_nonempty_password(self):
        passwords = self.vars['lab_team_passwords']
        self.assertEqual(set(passwords), set(self.vars['lab_attackers']))
        self.assertTrue(all(isinstance(p, str) and p for p in passwords.values()))
        self.assertEqual(len(set(passwords.values())), len(passwords), 'passwords must differ per team')

    def test_no_shared_console_password_or_platform_key_is_used(self):
        self.assertNotIn('lab_console_password', self.vars)
        self.assertNotIn('lab_console_password', self.playbook_text)
        self.assertNotIn('global_ssh_public_user_key', self.playbook_text)
        self.assertNotIn('user_access_ssh_public_key', self.attackers['vars'])
        self.assertEqual(self.attackers['vars']['user_access_password'],
                         '{{ lab_team_passwords[inventory_hostname] }}')

    def test_playbook_refuses_a_host_without_its_own_password(self):
        assertion = task(self.attackers['pre_tasks'], 'per-team console password')
        self.assertIn('inventory_hostname in lab_team_passwords', assertion['ansible.builtin.assert']['that'])

    def test_sshd_allows_only_passwords_for_the_trainee_account(self):
        content = task(self.attackers['tasks'], 'password-only login')['ansible.builtin.copy']['content']
        self.assertIn('Match User user-access', content)
        self.assertIn('PasswordAuthentication yes', content)
        self.assertIn('PubkeyAuthentication no', content)
        self.assertIn('AuthenticationMethods password', content)
        self.assertNotIn('PubkeyAuthentication yes', content)
        self.assertNotIn('AuthenticationMethods any', content)

    def test_leftover_authorized_keys_are_removed_and_sshd_is_reloaded_afterwards(self):
        tasks = self.attackers['tasks']
        removal = task(tasks, 'Remove any SSH keys')
        self.assertEqual(removal['ansible.builtin.file'],
                         {'path': '/home/user-access/.ssh/authorized_keys', 'state': 'absent'})
        self.assertEqual(removal['notify'], 'Reload attacker SSH')
        names = [t.get('name') for t in tasks]
        flush = [i for i, t in enumerate(tasks) if t.get('ansible.builtin.meta') == 'flush_handlers']
        self.assertTrue(flush, 'handlers must be flushed inside the attacker play')
        self.assertLess(names.index(removal['name']), flush[0])
        self.assertLess(names.index(task(tasks, 'password-only login')['name']), flush[0])

    def test_training_definition_does_not_reveal_team_passwords(self):
        text = (ROOT / 'training-definition.json').read_text(encoding='utf-8')
        for password in self.vars['lab_team_passwords'].values():
            self.assertNotIn(password, text)
        self.assertNotIn('ClientLab-Only-2026!', text)


class TeamServiceDeskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playbook = load_yaml('provisioning/playbook.yml')
        cls.attackers = play(cls.playbook, 'Give each attacker')
        cls.server = play(cls.playbook, 'Run ServiceDesk on the server VM')

    def test_team_unit_serves_the_team_config_on_8080_without_privileged_port(self):
        unit = (ROOT / 'provisioning/files/servicedesk@.service').read_text(encoding='utf-8')
        self.assertIn('--config /etc/idor-free-lab/%i.json', unit)
        self.assertIn('--host 0.0.0.0', unit)
        self.assertNotIn('CAP_NET_BIND_SERVICE', unit)
        included = task(self.attackers['tasks'],'every service declared')
        self.assertEqual(included['loop'],'{{ lab_services }}')

    def test_defender_can_patch_own_service_without_running_web_as_root(self):
        tasks = self.attackers['tasks']
        sudo = task(tasks, 'fixed per-instance unprivileged restart')['ansible.builtin.template']
        self.assertIn('visudo', sudo['validate'])
        instances=load_yaml('provisioning/service-instance.yml')
        application = task(instances, 'editable application files')['ansible.builtin.copy']
        self.assertEqual(application['owner'], 'user-access')
        self.assertIn('/services/{{ lab_service.id }}/', application['dest'])
        unit = (ROOT / 'provisioning/files/servicedesk@.service').read_text(encoding='utf-8')
        self.assertIn('User=free-lab-web', unit)
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertFalse(self.attackers['vars']['user_access_sudo'])

    def test_each_vm_gets_a_generated_password_before_any_service_uses_it(self):
        identity = play(self.playbook, 'Record the identity')
        generated = task(identity['tasks'], 'Generate a unique ServiceDesk password')
        self.assertIn('lab_generated_web_password', generated['ansible.builtin.set_fact'])
        self.assertIs(generated['no_log'], True)
        self.assertLess(self.playbook.index(identity), self.playbook.index(self.server))
        server_config=task(self.server['tasks'], 'Store ServiceDesk configuration')
        self.assertIn('password=lab_generated_web_password',server_config['ansible.builtin.copy']['content'])
        self.assertTrue(server_config['no_log'])
        generated=task(self.attackers['tasks'],'private per-service web passwords')
        self.assertTrue(generated['no_log'])
        self.assertEqual(generated['loop'],'{{ lab_services }}')

    def test_team_instance_identity_includes_the_host_name(self):
        instances=load_yaml('provisioning/service-instance.yml')
        config_task = task(instances, 'independent configuration and identity')
        self.assertIn("sandbox_id=global_sandbox_id ~ '-' ~ inventory_hostname",
                      config_task['ansible.builtin.copy']['content'])
        check = task(instances, 'Verify this service')
        self.assertIn('lab_service.port',check['ansible.builtin.uri']['url'])
        asserted = task(instances, 'correct sandbox and service identity')
        self.assertIn("global_sandbox_id ~ '-' ~ inventory_hostname", asserted['ansible.builtin.assert']['that'][0])

    def test_address_file_is_private_and_not_logged(self):
        addresses = task(self.attackers['tasks'], 'Write private service URLs')
        self.assertEqual(addresses['ansible.builtin.template']['mode'], '0600')
        self.assertIs(addresses['no_log'], True)
        template=(ROOT/'provisioning/templates/lab-addresses.j2').read_text(encoding='utf-8')
        self.assertIn('password SSH only',template)


class GatewayAndCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vars = load_yaml('provisioning/group_vars/all.yml')
        cls.gateway = load_json(GATEWAY / 'config.example.json')
        cls.definition = load_json(ROOT / 'training-definition.json')
        cls.attackers = [t['node'] for t in cls.vars['lab_teams']]

    def test_gateway_forwards_each_team_to_its_own_servicedesk(self):
        by_port = {s['gatewayPort']: s for s in self.gateway['services']}
        self.assertEqual(len(by_port), len(self.gateway['services']), 'gateway ports must be unique')
        for configured in self.vars['lab_services']:
            for offset, host in enumerate(self.attackers, start=1):
                service = by_port[configured['gateway_base_port'] + offset]
                self.assertEqual((service['sandboxIp'], service['sandboxPort']), (self.vars['lab_hosts'][host], configured['port']))
        shared = by_port[8080]
        self.assertEqual((shared['sandboxIp'], shared['sandboxPort']), (self.vars['lab_hosts']['server'], 80))

    def test_source_template_requires_allocation_configuration(self):
        ssh_config = self.gateway['sshConfig']
        self.assertEqual(ssh_config,'<USER_SSH_CONFIG>')
        self.assertEqual(self.gateway['gatewayIp'],'127.0.0.1')

    def test_training_definition_advertises_the_gateway_and_team_ports(self):
        text = self.definition['levels'][0]['cloud_content']
        self.assertIn('Configure-Deployment.ps1', text)
        for host in self.attackers:
            for s in self.vars['lab_services']:
                self.assertIn(f"http://{self.vars['lab_hosts'][host]}:{s['port']}/", text)

    def test_checker_targets_match_the_team_services(self):
        internal = load_json(ROOT / 'checker/web_targets.json')['targets']
        primary=self.vars['lab_services'][0]
        self.assertEqual([t['url'] for t in internal],
                         [f"http://{self.vars['lab_hosts'][h]}:{primary['port']}/health" for h in self.attackers])
        through_gateway = load_json(ROOT / 'checker/web_targets_gateway.example.json')['targets']
        self.assertEqual([t['name'] for t in through_gateway], [t['name'] for t in internal])
        self.assertEqual([t['url'] for t in through_gateway],
                         [f"http://{self.gateway['gatewayIp']}:{primary['gateway_base_port'] + i}/health" for i in range(1, len(self.attackers)+1)])


if __name__ == '__main__':
    unittest.main()
