from contextlib import ExitStack
from pathlib import Path
import tempfile
import threading
import unittest
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler
from app.portal import create_app,ThreadingWSGIServer
from checker.service_tick import check_tick_job


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass


class WorkflowTests(unittest.TestCase):
    def test_workflow_passes_after_owner_fix_and_rejects_wrong_service(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            identity=str(uuid4())+'-attacker1'
            app=create_app(Path(tmp)/'service.sqlite','example-alice-password',identity,True,'service02')
            server=stack.enter_context(make_server('127.0.0.1',0,app,server_class=ThreadingWSGIServer,handler_class=Quiet))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            stack.callback(thread.join,2);stack.callback(server.shutdown)
            job={'team':'team01','url':f'http://127.0.0.1:{server.server_port}/health','expected_sandbox':identity,
                 'service_id':'service02','expected_service':'service02','check_level':'workflow'}
            result=check_tick_job(job,16,3)
            self.assertEqual(result['status'],'UP',result)
            self.assertIn('create/list/read/update OK',result['detail'])
            wrong=check_tick_job({**job,'expected_service':'service01'},16,3)
            self.assertEqual(wrong['status'],'MUMBLE')
            # Keeping health alive while disabling application functions must fail.
            def broken(env,start):
                if env['PATH_INFO']=='/register':
                    raw=b'{"error":"disabled"}';start('405 Method Not Allowed',[('Content-Length',str(len(raw)))]);return [raw]
                return app(env,start)
            server.set_app(broken)
            failed=check_tick_job(job,17,3)
            self.assertEqual(failed['status'],'MUMBLE')


if __name__=='__main__':unittest.main()
