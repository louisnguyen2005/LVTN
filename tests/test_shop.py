"""Behavioral checks for the local web-shop challenge and its hardening switches."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPCookieProcessor,ProxyHandler,Request,build_opener
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import ThreadingWSGIServer
from app.shop import create_app
from checker.shop import check_shop_job


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass


class ShopVulnerabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        self.listeners=[]
    def tearDown(self):
        for server,thread in reversed(self.listeners):
            server.shutdown();server.server_close();thread.join(2)
        self.temp.cleanup()
    def listen(self,options=None):
        app=create_app(self.path/(str(len(self.listeners))+'.sqlite'),'known-customer-password-123',
            'sandbox-test-team01','shop01',options,merchant_password='known-merchant-password')
        server=make_server('127.0.0.1',0,app,server_class=ThreadingWSGIServer,handler_class=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.listeners.append((server,thread))
        return f'http://127.0.0.1:{server.server_port}'
    def client(self):return build_opener(ProxyHandler({}),HTTPCookieProcessor(CookieJar()))
    def call(self,client,url,data=None,expected=None):
        raw=json.dumps(data).encode() if data is not None else None
        req=Request(url,data=raw,headers={'Content-Type':'application/json','Accept':'application/json'})
        try:
            with client.open(req,timeout=5) as r:status=r.status;body=r.read()
        except HTTPError as exc:status=exc.code;body=exc.read()
        if expected is not None:self.assertEqual(status,expected,body)
        return status,json.loads(body) if body.startswith((b'{',b'[')) else body.decode(errors='replace')
    def login(self,client,base,user='alice',password='known-customer-password-123',captcha=True):
        _,c=self.call(client,base+'/api/captcha')
        if captcha:
            answer=str(sum(int(x.strip()) for x in c['question'].split('+')))
            payload={'captcha_id':c['id'],'captcha_answer':answer}
        else:payload={'captcha_verified':'1'}
        return self.call(client,base+'/api/login',{'username':user,'password':password,**payload})

    def test_captcha_bypass_switch_and_server_challenge(self):
        vulnerable=self.listen({'captcha_bypass':True})
        fixed=self.listen({'captcha_bypass':False})
        self.assertEqual(self.login(self.client(),vulnerable,'merchant','known-merchant-password',False)[0],200)
        self.assertEqual(self.login(self.client(),fixed,'merchant','known-merchant-password',False)[0],400)
        self.assertEqual(self.login(self.client(),fixed,'merchant','known-merchant-password',True)[0],200)

    def test_sql_injection_discloses_a_private_flag_only_when_enabled(self):
        for enabled in (True,False):
            base=self.listen({'sqli':enabled});client=self.client();self.login(client,base)
            _,order=self.call(client,base+'/api/orders',{'product_id':1,'quantity':1,'shipping_address':'lab','private_note':'FLAG{shop_flag_proof}'})
            payload="%' UNION SELECT id,owner,total,private_note FROM orders -- "
            _,rows=self.call(client,base+'/api/products?q='+quote(payload,safe=''))
            leaked=any('FLAG{shop_flag_proof}' in str(row.values()) for row in rows)
            self.assertEqual(leaked,enabled)
            self.assertIsInstance(order['id'],int)

    def test_stored_xss_is_raw_only_when_enabled(self):
        payload='<img src=x onerror=window.__novaXss=true>'
        for enabled in (True,False):
            base=self.listen({'xss':enabled});client=self.client();self.login(client,base)
            self.call(client,base+'/api/reviews',{'content':payload},201)
            req=Request(base+'/reviews')
            with build_opener(ProxyHandler({})).open(req,timeout=5) as r:html=r.read().decode()
            self.assertEqual(payload in html,enabled)
            if not enabled:self.assertIn('&lt;img',html)

    def test_csrf_order_share_is_state_changing_get_only_when_enabled(self):
        for enabled in (True,False):
            base=self.listen({'csrf':enabled});client=self.client();login=self.login(client,base)[1]
            self.call(client,base+'/api/register',{'username':'bobby','password':'bob-password-long-123'},201)
            _,order=self.call(client,base+'/api/orders',{'product_id':1,'quantity':1,'shipping_address':'lab','private_note':'flag','csrf_token':login['csrf_token']})
            status,_=self.call(client,base+f"/api/orders/share?order_id={order['id']}&recipient=bobby")
            self.assertEqual(status,200 if enabled else 405)

    def test_rate_limit_switch_blocks_sixth_failed_attempt(self):
        for enabled in (True,False):
            base=self.listen({'brute_force':enabled,'captcha_bypass':True});client=self.client();codes=[]
            for _ in range(6):codes.append(self.call(client,base+'/api/login',{'username':'merchant','password':'wrong','captcha_verified':'1'})[0])
            self.assertEqual(codes[-1],401 if enabled else 429)

    def test_functional_checker_stays_up_when_all_challenge_paths_are_patched(self):
        switches={name:False for name in ('sqli','captcha_bypass','xss','csrf','brute_force')}
        base=self.listen(switches);ident='a'*32
        result=check_shop_job({'team':'team01','service_id':'shop01','url':base+'/health',
            'expected_sandbox':'sandbox-test-team01','current':{'id':ident,'username':'check_'+ident[:24],
            'password':'checker-password-123','value':'FLAG{integration-test}'},'previous':[]},1)
        self.assertEqual(result['status'],'UP',result)
        self.assertIsInstance(result['object_id'],int)


if __name__=='__main__':unittest.main()
