"""One service measurement for a team in a scheduled tick: health, functional, or flag PUT/GET."""
from .flag_checker import run_flag_check
from .web_health import check_web,check_service


def check_flag_job(job,tick,timeout=3):
    """CHECK the service, PUT this tick's flag through the normal API, GET every still-valid flag."""
    result=run_flag_check(job,timeout)
    # actions/flags are the per-step trace the backend stores in checker_actions and flag_checks.
    return {'tick':tick,'team':job['team'],'service_id':job['service_id'],'flag_id':job['current']['id'],
            'ticket_id':result['ticket_id'],'status':result['status'],'detail':result['detail'],
            'elapsed_ms':result['elapsed_ms'],'actions':result['actions'],'flags':result['flags']}


def check_tick_job(job,tick,timeout=3):
    if job.get('check_level')=='flag':
        return check_flag_job(job,tick,timeout)
    target={'name':job['team'],'url':job['url'],'expected_sandbox':job['expected_sandbox']}
    if job.get('check_level')=='functional':
        result=check_service(target,job['password'],timeout)
    else:
        result=check_web(target,timeout)
    if result['status']=='MUMBLE' and result.get('detail','').startswith('HTTP 5'):
        result['status']='DOWN'
    return {'tick':tick,'team':job['team'],'service_id':job['service_id'],
            'status':result['status'],'detail':result.get('detail',''),
            'elapsed_ms':result['elapsed_ms']}
