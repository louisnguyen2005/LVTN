import importlib.util
import io
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from contextlib import ExitStack
import threading
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, HTTPCookieProcessor, build_opener
from wsgiref.simple_server import make_server, WSGIRequestHandler
from pathlib import Path
from urllib.parse import urlencode
import yaml

ROOT = Path(__file__).resolve().parents[1]


class PortalTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / 'app/portal.py'
        self.assertTrue(source.exists(), 'New helpdesk lab implementation is required')
        spec = importlib.util.spec_from_file_location('portal', source)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = self.module.create_app(Path(self.temp.name) / 'a.sqlite', 'lab-password', 'sandbox-A')

    def request(self, path, method='GET', data=None, cookie='', app=None):
        body = urlencode(data or {}).encode()
        env = {'PATH_INFO': path, 'REQUEST_METHOD': method, 'HTTP_COOKIE': cookie,
               'CONTENT_LENGTH': str(len(body)), 'wsgi.input': io.BytesIO(body)}
        result = {}
        def start(status, headers):
            result.update(status=int(status.split()[0]), headers=dict(headers))
        result['body'] = b''.join((app or self.app)(env, start))
        return result

    def login(self, app=None):
        result = self.request('/login', 'POST', {'username': 'alice', 'password': 'lab-password'}, app=app)
        self.assertEqual(result['status'], 200)
        self.assertIn('HttpOnly', result['headers']['Set-Cookie'])
        return result['headers']['Set-Cookie'].split(';')[0]

    def test_real_portal_and_own_ticket_list(self):
        page = self.request('/')
        self.assertEqual(page['status'], 200)
        self.assertIn(b'ServiceDesk', page['body'])
        response = self.request('/api/tickets', cookie=self.login())
        tickets = json.loads(response['body'])
        self.assertEqual([t['id'] for t in tickets], [1201])
        self.assertEqual(tickets[0]['owner'], 'alice')

    def test_read_and_write_idor(self):
        cookie = self.login()
        other = self.request('/api/tickets/1401', cookie=cookie)
        self.assertEqual(other['status'], 200)
        self.assertEqual(json.loads(other['body'])['owner'], 'bob')
        update = self.request('/api/tickets/1401', 'POST', {'status': 'closed'}, cookie)
        self.assertEqual(update['status'], 200)
        self.assertEqual(json.loads(self.request('/api/tickets/1401', cookie=cookie)['body'])['status'], 'closed')

    def test_owner_check_protects_read_and_write(self):
        fixed = self.module.create_app(Path(self.temp.name) / 'fixed.sqlite', 'lab-password', 'fixed', True)
        cookie = self.login(fixed)
        self.assertEqual(self.request('/api/tickets/1201', cookie=cookie, app=fixed)['status'], 200)
        for method in ['GET', 'POST']:
            self.assertEqual(self.request('/api/tickets/1401', method, {'status': 'closed'}, cookie, fixed)['status'], 403)

    def test_session_and_data_are_separate_between_sandboxes(self):
        second = self.module.create_app(Path(self.temp.name) / 'b.sqlite', 'lab-password', 'sandbox-B')
        cookie_a = self.login()
        self.assertEqual(self.request('/api/tickets', cookie=cookie_a, app=second)['status'], 401)
        self.request('/api/tickets/1401', 'POST', {'status': 'closed'}, cookie_a)
        cookie_b = self.login(second)
        b = json.loads(self.request('/api/tickets/1401', cookie=cookie_b, app=second)['body'])
        self.assertEqual(b['status'], 'open')
        self.assertIn('sandbox-B', b['private_note'])

    def test_unauthenticated_wrong_login_and_logout(self):
        self.assertEqual(self.request('/api/tickets/1401')['status'], 401)
        self.assertEqual(self.request('/login', 'POST', {'username': 'alice', 'password': 'wrong'})['status'], 401)
        cookie = self.login()
        self.assertEqual(self.request('/logout', 'POST', cookie=cookie)['status'], 200)
        self.assertEqual(self.request('/api/tickets', cookie=cookie)['status'], 401)

    def test_input_validation_and_missing_records(self):
        cookie = self.login()
        for path in ['/missing', '/api/tickets/not-a-number', '/api/tickets/9999']:
            self.assertEqual(self.request(path, cookie=cookie)['status'], 404)
        self.assertEqual(self.request('/api/tickets/1201', 'POST', {'status': 'bad'}, cookie)['status'], 400)
        self.assertEqual(self.request('/api/tickets/1201', 'DELETE', cookie=cookie)['status'], 405)

    def test_restart_preserves_ticket_changes_but_not_sessions(self):
        cookie = self.login()
        self.request('/api/tickets/1201', 'POST', {'status': 'closed'}, cookie)
        restarted = self.module.create_app(Path(self.temp.name) / 'a.sqlite', 'lab-password', 'sandbox-A')
        self.assertEqual(self.request('/api/tickets', cookie=cookie, app=restarted)['status'], 401)
        new_cookie = self.login(restarted)
        result = self.request('/api/tickets/1201', cookie=new_cookie, app=restarted)
        self.assertEqual(json.loads(result['body'])['status'], 'closed')

    def test_boundaries_expiry_health_and_config_entrypoint(self):
        self.assertEqual(json.loads(self.request('/health')['body'])['sandbox'], 'sandbox-A')
        with self.assertRaises(ValueError):
            self.module.create_app(Path(self.temp.name) / 'empty.sqlite', '', 'sandbox')
        with patch.object(self.module.time, 'time', return_value=1000):
            cookie = self.login()
        with patch.object(self.module.time, 'time', return_value=3000):
            self.assertEqual(self.request('/api/tickets', cookie=cookie)['status'], 401)
            self.login()
        for length, body, expected in [('bad', b'', 400), ('5000', b'', 413), ('1', b'\xff', 400)]:
            env = {'PATH_INFO': '/login', 'REQUEST_METHOD': 'POST', 'CONTENT_LENGTH': length, 'wsgi.input': io.BytesIO(body)}
            result = {}
            self.app(env, lambda status, headers: result.update(status=int(status.split()[0])))
            self.assertEqual(result['status'], expected)
        config = Path(self.temp.name) / 'config.json'
        config.write_text(json.dumps({'database': str(Path(self.temp.name) / 'cli.sqlite'), 'password': 'lab-password', 'sandbox_id': 'cli'}), encoding='utf-8')
        listener = MagicMock()
        with patch('sys.argv', ['portal.py', '--config', str(config), '--host', '0.0.0.0', '--port', '80']), patch.object(self.module, 'make_server', return_value=listener) as make:
            self.module.main()
        self.assertEqual(make.call_args.args[:2], ('0.0.0.0', 80))
        listener.__enter__.return_value.serve_forever.assert_called_once()

    def test_two_actual_http_servers_keep_writes_separate(self):
        class QuietHandler(WSGIRequestHandler):
            def log_message(self, *args):
                pass
        second = self.module.create_app(Path(self.temp.name) / 'http-b.sqlite', 'lab-password', 'sandbox-B')
        with ExitStack() as stack:
            urls = []
            for app in [self.app, second]:
                server = stack.enter_context(make_server('127.0.0.1', 0, app, handler_class=QuietHandler))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                stack.callback(thread.join, 2)
                stack.callback(server.shutdown)
                urls.append(f'http://127.0.0.1:{server.server_port}')
            clients = [build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar())) for _ in urls]
            for client, url in zip(clients, urls):
                with self.assertRaises(HTTPError) as failure:
                    client.open(url + '/api/tickets/1401', timeout=5)
                self.assertEqual(failure.exception.code, 401)
                login = Request(url + '/login', data=urlencode({'username': 'alice', 'password': 'lab-password'}).encode())
                with client.open(login, timeout=5) as response:
                    self.assertEqual(json.load(response)['user'], 'alice')
            write = Request(urls[0] + '/api/tickets/1401', data=b'status=closed')
            with clients[0].open(write, timeout=5) as response:
                self.assertEqual(json.load(response)['status'], 'closed')
            with clients[1].open(urls[1] + '/api/tickets/1401', timeout=5) as response:
                ticket_b = json.load(response)
                self.assertEqual(ticket_b['status'], 'open')
                self.assertIn('sandbox-B', ticket_b['private_note'])


class DefinitionTests(unittest.TestCase):
    def test_free_lab_uses_native_access_level_for_topology(self):
        source = ROOT / 'training-definition.json'
        self.assertTrue(source.exists(), 'Free lab definition is required')
        definition = json.loads(source.read_text(encoding='utf-8'))
        self.assertFalse(definition['variant_sandboxes'])
        self.assertFalse(definition['show_stepper_bar'])
        self.assertEqual(len(definition['levels']), 1)
        level = definition['levels'][0]
        self.assertEqual(level['level_type'], 'ACCESS_LEVEL')
        self.assertEqual(level['title'], 'Five-host IDOR Lab')
        self.assertEqual(level['passkey'], 'finish-idor-lab')
        self.assertIn('finish-idor-lab', level['cloud_content'])
        for address in ['10.80.0.11', '10.80.0.12', '10.80.0.13', '10.80.0.14']:
            self.assertIn('http://' + address + '/', level['cloud_content'])
        self.assertIn('10.80.0.20', level['cloud_content'])
        self.assertIn('blocked', level['cloud_content'])
        self.assertTrue(level['local_content'].strip())
        for key in ['answer', 'answer_variable_name', 'questions', 'max_score', 'content']:
            self.assertNotIn(key, level)

    def test_one_sandbox_has_four_attackers_and_one_server(self):
        source = ROOT / 'topology.yml'
        self.assertTrue(source.exists(), 'Isolated lab topology is required')
        topology = yaml.safe_load(source.read_text(encoding='utf-8'))
        self.assertEqual({h['name'] for h in topology['hosts']},
                         {'attacker1', 'attacker2', 'attacker3', 'attacker4', 'server'})
        self.assertEqual(len(topology['networks']), 1)
        self.assertEqual(len(topology['routers']), 1)
        self.assertEqual(len(topology['net_mappings']), 5)
        self.assertEqual(topology['groups'], [
            {'name': 'attackers', 'nodes': ['attacker1', 'attacker2', 'attacker3', 'attacker4']}
        ])
        self.assertEqual({m['ip'] for m in topology['net_mappings']},
                         {'10.80.0.11', '10.80.0.12', '10.80.0.13', '10.80.0.14', '10.80.0.20'})
        self.assertEqual(topology['router_mappings'][0]['ip'], '10.80.0.1')
        self.assertFalse((ROOT / 'interconnect').exists())
        self.assertFalse((ROOT / 'variables.yml').exists())


if __name__ == '__main__':
    unittest.main()
