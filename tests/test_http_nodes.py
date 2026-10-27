import importlib.util
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import ProxyHandler, build_opener


ROOT = Path(__file__).resolve().parents[1]


class AttackerHTTPTests(unittest.TestCase):
    def test_each_attacker_identifies_itself_over_http(self):
        source = ROOT / 'app/attacker_http.py'
        spec = importlib.util.spec_from_file_location('attacker_http', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        opener = build_opener(ProxyHandler({}))
        for node in ['attacker1', 'attacker2', 'attacker3', 'attacker4']:
            with ThreadingHTTPServer(('127.0.0.1', 0), module.handler_for(node)) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    base = f'http://127.0.0.1:{server.server_port}'
                    with opener.open(base + '/health', timeout=3) as response:
                        self.assertEqual(json.load(response), {'node': node})
                    with opener.open(base + '/', timeout=3) as response:
                        self.assertIn(node.encode(), response.read())
                finally:
                    server.shutdown()
                    thread.join(timeout=3)

    def test_port_80_and_no_server_forwarding_are_provisioned(self):
        playbook = (ROOT / 'provisioning/playbook.yml').read_text(encoding='utf-8')
        attacker_unit = (ROOT / 'provisioning/files/attacker-http@.service').read_text(encoding='utf-8')
        server_unit = (ROOT / 'provisioning/files/servicedesk.service').read_text(encoding='utf-8')
        self.assertIn('hosts: attackers', playbook)
        self.assertIn('hosts: server', playbook)
        self.assertIn('name: net.ipv4.ip_forward', playbook)
        self.assertIn('value: \'0\'', playbook)
        self.assertIn('hosts: attackers', playbook)
        self.assertIn('state: stopped', playbook)
        acl = (ROOT / 'provisioning/files/server-acl.nft').read_text(encoding='utf-8')
        self.assertIn('ct state new drop', acl)
        self.assertIn('ip saddr 10.80.0.0/24', acl)
        self.assertIn('10.80.0.20', acl)
        for unit in [attacker_unit, server_unit]:
            self.assertIn('--host 0.0.0.0 --port 80', unit)
            self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', unit)


if __name__ == '__main__':
    unittest.main()
