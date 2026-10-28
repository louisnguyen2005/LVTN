"""Exercise normal ServiceDesk functions without privileged checker credentials."""
from http.cookiejar import CookieJar
import secrets
import time
from urllib.error import HTTPError,URLError
from urllib.parse import urlencode,urlsplit
from urllib.request import Request,build_opener,ProxyHandler,HTTPCookieProcessor
from .web_health import check_web,NoRedirect,read_json_bounded


def check_workflow(target,timeout):
    result=check_web(target,timeout)
    if result['status']!='UP':return result
    started=time.monotonic()
    parsed=urlsplit(target['url']);base=f'{parsed.scheme}://{parsed.netloc}'
    opener=build_opener(ProxyHandler({}),NoRedirect(),HTTPCookieProcessor(CookieJar()))
    username='sla_'+secrets.token_hex(12);password=secrets.token_urlsafe(24)
    marker='sla-probe:'+secrets.token_hex(20)
    def call(path,data=None):
        req=Request(base+path,data=urlencode(data).encode() if data is not None else None,
                    headers={'Accept':'application/json'})
        with opener.open(req,timeout=timeout) as response:return read_json_bounded(response)
    try:
        if call('/register',{'username':username,'password':password}).get('user')!=username:
            raise ValueError('Registration failed')
        if call('/login',{'username':username,'password':password}).get('user')!=username:
            raise ValueError('Login failed')
        created=call('/api/tickets',{'title':'Service availability probe','private_note':marker})
        ident=created['id']
        if type(ident) is not int or created.get('owner')!=username:
            raise ValueError('Ticket creation failed')
        rows=call('/api/tickets')
        if not isinstance(rows,list) or not any(r.get('id')==ident and r.get('owner')==username for r in rows):
            raise ValueError('Created ticket is missing from list')
        ticket=call('/api/tickets/'+str(ident))
        if ticket.get('owner')!=username or ticket.get('private_note')!=marker:
            raise ValueError('Ticket read failed')
        changed=call('/api/tickets/'+str(ident),{'status':'closed'})
        if changed.get('status')!='closed' or call('/api/tickets/'+str(ident)).get('status')!='closed':
            raise ValueError('Ticket update failed')
        result['detail']='Health, registration, login, ticket create/list/read/update OK'
    except HTTPError as exc:
        result.update(status='DOWN' if exc.code>=500 else 'MUMBLE',detail=f'HTTP {exc.code} during service workflow')
    except (URLError,TimeoutError,ConnectionError,OSError):
        result.update(status='DOWN',detail='Service workflow connection failed or timed out')
    except (ValueError,TypeError,KeyError,AttributeError):
        result.update(status='MUMBLE',detail='Service workflow response failed validation')
    except Exception:
        result.update(status='ERROR',detail='Unexpected workflow checker exception')
    result['elapsed_ms']+=round((time.monotonic()-started)*1000)
    return result
