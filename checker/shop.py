"""Functional checker for the intentionally vulnerable NOVA MART service."""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener
from http.cookiejar import CookieJar


def _request(client, url, timeout, payload=None):
    data=json.dumps(payload).encode() if payload is not None else None
    req=Request(url,data=data,headers={'Accept':'application/json','Content-Type':'application/json'})
    with client.open(req,timeout=timeout) as response:
        raw=response.read(65537)
        if len(raw)>65536: raise ValueError('Shop response exceeds size limit')
        return json.loads(raw)


def _login(client, base, identity, timeout):
    challenge=_request(client,base+'/api/captcha',timeout)
    values=[int(v.strip()) for v in challenge['question'].split('+')]
    _request(client,base+'/api/login',timeout,{'username':identity['username'],'password':identity['password'],
        'captcha_id':challenge['id'],'captcha_answer':str(sum(values))})
    return _request(client,base+'/api/me',timeout)['csrf_token']


def check_shop_job(job, tick, timeout=3):
    started=time.monotonic(); current=job['current']
    result={'tick':tick,'team':job['team'],'service_id':job['service_id'],'status':'ERROR',
        'elapsed_ms':0,'detail':'','flag_id':current['id'],'object_id':None}
    base=job['url'].removesuffix('/health').rstrip('/')
    stage='health'
    try:
        client=build_opener(ProxyHandler({}),HTTPCookieProcessor(CookieJar()))
        health=_request(client,base+'/health',timeout)
        if health.get('status')!='ok' or health.get('sandbox')!=job['expected_sandbox'] or health.get('service')!=job['service_id'] or 'shop-v1' not in health.get('capabilities',[]):
            raise ValueError('Wrong NOVA MART sandbox/service identity')
        # The checker solves the real one-use challenge and never relies on CAPTCHA bypass.
        try:_request(client,base+'/api/register',timeout,{'username':current['username'],'password':current['password']})
        except HTTPError as exc:
            if exc.code!=409: raise
        stage='login';csrf=_login(client,base,current,timeout)
        reference='ctf-'+current['id']
        stage='place order'
        order=_request(client,base+'/api/orders',timeout,{'product_id':1,'quantity':1,
            'shipping_address':'Competition delivery desk','private_note':current['value'],'reference':reference,'csrf_token':csrf})
        order_id=order.get('id')
        if type(order_id) is not int or order.get('owner')!=current['username']:
            raise ValueError('Checker could not place its assigned flag order')
        stage='read current order';fetched=_request(client,base+f'/api/orders/{order_id}',timeout)
        if fetched.get('private_note')!=current['value'] or fetched.get('owner')!=current['username']:
            raise ValueError('Placed flag cannot be read back by its owner')
        # Verify every still-live flag on this service remains retrievable after this tick.
        for old in job.get('previous',[]):
            previous=build_opener(ProxyHandler({}),HTTPCookieProcessor(CookieJar()))
            stage='login to previous flag';_login(previous,base,old,timeout)
            stage='read previous order'
            old_order=_request(previous,base+f"/api/orders/{old['object_id']}",timeout)
            if old_order.get('private_note')!=old['value'] or old_order.get('owner')!=old['username']:
                raise ValueError('An active previous tick flag is missing or changed')
        result.update(status='UP',detail='Health, CAPTCHA login, order PUT/GET and active flags OK',object_id=order_id)
    except HTTPError as exc:
        result.update(status='DOWN' if exc.code>=500 else 'MUMBLE',detail=f'HTTP {exc.code} during {stage}')
    except (URLError,TimeoutError,ConnectionError,OSError):
        result.update(status='DOWN',detail='NOVA MART connection failed or timed out')
    except (ValueError,KeyError,TypeError,AttributeError,IndexError) as exc:
        result.update(status='MUMBLE',detail=str(exc) if isinstance(exc,ValueError) else 'Invalid shop response')
    except Exception:
        result.update(status='ERROR',detail='Unexpected checker exception')
    result['elapsed_ms']=round((time.monotonic()-started)*1000)
    return result
