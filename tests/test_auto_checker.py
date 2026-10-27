"""Exercise the automatic checker against actual local ServiceDesk instances."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from uuid import uuid4
from wsgiref.simple_server import make_server


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
from portal import create_app, ThreadingWSGIServer  # noqa: E402


class AutomaticCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sandbox_id = str(uuid4())
        self.servers = []
        self.threads = []
        targets = []
        services = []
        for number in range(1, 5):
            app = create_app(self.root / f'team{number}.sqlite', 'example-password',
                             f'{self.sandbox_id}-attacker{number}')
            server = make_server('127.0.0.1', 0, app, server_class=ThreadingWSGIServer)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.servers.append(server)
            self.threads.append(thread)
            targets.append({
                'name': f'team{number:02d}',
                'url': f'http://127.0.0.1:{server.server_port}/health',
                'expected_sandbox_suffix': f'-attacker{number}',
            })
            services.append({'gatewayPort': server.server_port})
        self.targets = targets
        self.target_path = self.root / 'targets.json'
        self.gateway_path = self.root / 'gateway.json'
        self.output_dir = self.root / 'results'
        self.target_path.write_text(json.dumps({'targets': targets}), encoding='utf-8')
        self.gateway_path.write_text(json.dumps({
            'sshConfig': f'pool-id-1-sandbox-id-{self.sandbox_id}-user-config',
            'gatewayIp': '127.0.0.1',
            'services': services,
        }), encoding='utf-8')

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def run_checker(self, credentials=None, rounds=1):
        command = [
            sys.executable, str(ROOT / 'checker' / 'auto_check.py'),
            '--config', str(self.target_path),
            '--gateway-config', str(self.gateway_path),
            '--output-dir', str(self.output_dir),
            '--interval', '0.01', '--timeout', '0.5', '--rounds', str(rounds),
        ]
        if credentials is not None:
            credentials_path = self.root / 'credentials.json'
            credentials_path.write_text(json.dumps(credentials), encoding='utf-8')
            command.extend(['--credentials', str(credentials_path)])
        return subprocess.run(command, capture_output=True, text=True, timeout=10)

    def latest(self):
        return json.loads((self.output_dir / 'latest.json').read_text(encoding='utf-8'))

    def test_records_up_down_and_wrong_team_identity(self):
        first = self.run_checker()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(self.latest()['all_up'])
        self.assertEqual(len(self.latest()['results']), 4)

        self.servers[1].shutdown()
        self.servers[1].server_close()
        second = self.run_checker()
        self.assertEqual(second.returncode, 1, second.stderr)
        statuses = {row['name']: row['status'] for row in self.latest()['results']}
        self.assertEqual(statuses['team02'], 'DOWN')
        self.assertTrue(all(status == 'UP' for name, status in statuses.items() if name != 'team02'))

        switched = list(self.targets)
        switched[0] = {**switched[0], 'url': self.targets[2]['url']}
        switched[2] = {**switched[2], 'url': self.targets[0]['url']}
        self.target_path.write_text(json.dumps({'targets': switched}), encoding='utf-8')
        third = self.run_checker()
        self.assertEqual(third.returncode, 1, third.stderr)
        details = {row['name']: row['detail'] for row in self.latest()['results']}
        statuses = {row['name']: row['status'] for row in self.latest()['results']}
        self.assertEqual(statuses['team01'], 'MUMBLE')
        self.assertEqual(statuses['team03'], 'MUMBLE')
        self.assertIn('Wrong sandbox identity', details['team01'])
        self.assertIn('Wrong sandbox identity', details['team03'])

        history = (self.output_dir / 'history.jsonl').read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(history), 3)
        self.assertTrue(json.loads(history[0])['all_up'])
        self.assertFalse(json.loads(history[1])['all_up'])

    def test_functional_check_requires_valid_team_credentials(self):
        credentials = {f'team{number:02d}': 'example-password' for number in range(1, 5)}
        good = self.run_checker(credentials)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(self.latest()['check_level'], 'functional')
        self.assertTrue(self.latest()['all_up'])

        credentials['team03'] = 'incorrect-password'
        bad = self.run_checker(credentials)
        self.assertEqual(bad.returncode, 1, bad.stderr)
        statuses = {row['name']: row['status'] for row in self.latest()['results']}
        self.assertEqual(statuses['team03'], 'MUMBLE')
        self.assertTrue(all(status == 'UP' for name, status in statuses.items() if name != 'team03'))

    def test_periodic_runner_saves_each_round(self):
        completed = self.run_checker(rounds=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        history = (self.output_dir / 'history.jsonl').read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(history), 2)
        self.assertTrue(all(json.loads(line)['all_up'] for line in history))


if __name__ == '__main__':
    unittest.main()
