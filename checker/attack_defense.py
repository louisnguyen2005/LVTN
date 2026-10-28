"""ServiceDesk adapter for the per-round event mode: CHECK, PUT a flag, GET active flags."""
from .flag_checker import NoRedirect, client, request, run_flag_check  # noqa: F401  (re-exported)


def check_job(job,number,timeout=3):
    traced = run_flag_check(job,timeout)
    # Round mode predates CORRUPT; a lost older flag is reported as MUMBLE there.
    status = 'MUMBLE' if traced['status']=='CORRUPT' else traced['status']
    return {'round':number,'team':job['team'],'flag_id':job['current']['id'],'status':status,
            'ticket_id':traced['ticket_id'],'elapsed_ms':traced['elapsed_ms'],'detail':traced['detail']}
