import importlib.util
import json
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, ProxyHandler, HTTPCookieProcessor, build_opener
from http.cookiejar import CookieJar
from wsgiref.simple_server import make_server, WSGIRequestHandler
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load_portal():
    source = ROOT / 'app/score_portal.py'
    spec = importlib.util.spec_from_file_location('score_portal', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PortalOverHTTPTests(unittest.TestCase):
    def test_full_idor_chain_over_a_real_http_server(self):
        module = load_portal()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        flag = 'MeKoDataCTF{team03_c1a05e94}'
        app = module.create_app(Path(temp.name) / 'http.sqlite', 'team03_mekodatactf_2026_test1',
                                'sandbox-http', flag, student_id=20260301)

        class QuietHandler(WSGIRequestHandler):
            def log_message(self, *args):
                pass

        with make_server('127.0.0.1', 0, app, handler_class=QuietHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                client = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
                # Step 1: point.js is served fresh and documents the API map.
                with client.open(base + '/static/point.js', timeout=5) as response:
                    script = response.read().decode('utf-8')
                self.assertIn('/api/scores/', script)
                self.assertIn('9000', script)
                self.assertNotIn(flag, script)
                # Step 2: log in, then read own profile and score list.
                login = Request(base + '/login', data=urlencode(
                    {'username': 'student', 'password': 'team03_mekodatactf_2026_test1'}).encode())
                with client.open(login, timeout=5) as response:
                    self.assertEqual(json.load(response)['user'], 'student')
                with client.open(base + '/api/scores', timeout=5) as response:
                    own = json.load(response)
                self.assertEqual([r['record_id'] for r in own], [1001, 1002, 1003])
                # Step 3 + 4: change the recordId (IDOR) to reach the hidden audit flag.
                with client.open(base + '/api/scores/9001', timeout=5) as response:
                    self.assertIn(flag, json.load(response)['remark'])
            finally:
                server.shutdown()
                thread.join(timeout=3)


class ProvisioningTests(unittest.TestCase):
    def test_port_80_portal_is_provisioned_on_each_team(self):
        playbook = (ROOT / 'provisioning/playbook.yml').read_text(encoding='utf-8')
        unit = (ROOT / 'provisioning/files/score-portal.service').read_text(encoding='utf-8')
        self.assertIn('hosts: teams', playbook)
        self.assertIn('score_portal.py', playbook)
        self.assertIn('point.js', playbook)
        self.assertIn("team_secrets[inventory_hostname].flag", playbook)
        self.assertIn("team_secrets[inventory_hostname].password", playbook)
        self.assertIn('--host 0.0.0.0 --port 80', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', unit)
        # The obsolete central-server pieces must be gone.
        for gone in ['server-acl.nft', 'attacker-http', 'servicedesk.service', 'ip_forward']:
            self.assertNotIn(gone, playbook)
        self.assertFalse((ROOT / 'provisioning/files/server-acl.nft').exists())
        self.assertFalse((ROOT / 'app/attacker_http.py').exists())


if __name__ == '__main__':
    unittest.main()
