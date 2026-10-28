"""ServiceDesk adapter: CHECK, PUT a flag using normal API, GET active flags."""
from http.cookiejar import CookieJar
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, HTTPCookieProcessor, Request, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def client():
    return build_opener(ProxyHandler({}),NoRedirect(),HTTPCookieProcessor(CookieJar()))


def request(opener,url,timeout,data=None):
    payload = urlencode(data).encode() if data is not None else None
    req = Request(url,data=payload,headers={'Accept':'application/json'})
    with opener.open(req,timeout=timeout) as response:
        raw = response.read(65537)
        if len(raw)>65536:
            raise ValueError('Service response too large')
        return json.loads(raw)


def check_job(job,number,timeout=3):
    started = time.monotonic()
    current = job['current']
    result = {'round':number,'team':job['team'],'flag_id':current['id'],
              'status':'ERROR','ticket_id':None,'elapsed_ms':0,'detail':''}
    base = job['url'].rstrip('/')
    try:
        opener = client()
        health = request(opener,base+'/health',timeout)
        if health.get('status')!='ok' or health.get('sandbox')!=job['expected_sandbox']:
            raise ValueError('Wrong service health or sandbox identity')
        if 'tickets-v2' not in health.get('capabilities',[]):
            raise ValueError('Reprovision ServiceDesk: tickets-v2 is required')
        # Each round has a new ordinary account; no privileged checker endpoint.
        try:
            request(opener,base+'/register',timeout,{'username':current['username'],'password':current['password']})
        except HTTPError as exc:
            if exc.code!=409:
                raise
        login = request(opener,base+'/login',timeout,{'username':current['username'],'password':current['password']})
        if login.get('user')!=current['username']:
            raise ValueError('Wrong login identity')
        title = 'Service request '+current['id']
        tickets = request(opener,base+'/api/tickets',timeout)
        if not isinstance(tickets,list):
            raise ValueError('Invalid ticket list')
        matching = [t for t in tickets if t.get('title')==title and t.get('owner')==current['username']]
        if matching:
            ticket_id = matching[0]['id']
        else:
            ticket_id = request(opener,base+'/api/tickets',timeout,{'title':title,'private_note':current['value']})['id']
        if type(ticket_id) is not int or ticket_id<1:
            raise ValueError('Invalid ticket identifier')
        ticket = request(opener,base+f'/api/tickets/{ticket_id}',timeout)
        if ticket.get('owner')!=current['username'] or ticket.get('private_note')!=current['value']:
            raise ValueError('New flag cannot be retrieved by its owner')
        result['ticket_id'] = ticket_id
        for old in job['previous']:
            previous_client = client()
            request(previous_client,base+'/login',timeout,{'username':old['username'],'password':old['password']})
            ticket = request(previous_client,base+f"/api/tickets/{old['ticket_id']}",timeout)
            if ticket.get('owner')!=old['username'] or ticket.get('private_note')!=old['value']:
                raise ValueError('A previous active flag is missing or changed')
        result.update(status='UP',detail='CHECK, PUT, GET and previous active flags OK')
    except HTTPError as exc:
        result.update(status='MUMBLE',detail=f'HTTP {exc.code} during service check')
    except (URLError,TimeoutError,ConnectionError,OSError):
        result.update(status='DOWN',detail='Service connection failed or timed out')
    except (ValueError,KeyError,TypeError,AttributeError) as exc:
        result.update(status='MUMBLE',detail=str(exc) if isinstance(exc,ValueError) else 'Invalid service response')
    except Exception:
        result.update(status='ERROR',detail='Unexpected checker exception')
    result['elapsed_ms'] = round((time.monotonic()-started)*1000)
    return result
