"""One read-only service measurement for a team in a scheduled SLA tick."""
from .web_health import check_web,check_service
from .servicedesk import check_workflow
from .shop import check_shop_job


def check_tick_job(job,tick,timeout=3):
    if job.get('check_level')=='shop':
        return check_shop_job(job,tick,timeout)
    target={'name':job['team'],'url':job['url'],'expected_sandbox':job['expected_sandbox']}
    if job.get('expected_service'):target['expected_service']=job['expected_service']
    if job.get('check_level')=='workflow':
        result=check_workflow(target,timeout)
    elif job.get('check_level')=='functional':
        result=check_service(target,job['password'],timeout)
    else:
        result=check_web(target,timeout)
    if result['status']=='MUMBLE' and result.get('detail','').startswith('HTTP 5'):
        result['status']='DOWN'
    return {'tick':tick,'team':job['team'],'service_id':job['service_id'],
            'status':result['status'],'detail':result.get('detail',''),
            'elapsed_ms':result['elapsed_ms']}
