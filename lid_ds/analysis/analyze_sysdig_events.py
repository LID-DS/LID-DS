

def thread_events(sysdig_events):
    for thread_id in _distinct_thread_ids(sysdig_events):
        yield thread_id, thread_events_for_thread_id(sysdig_events, thread_id)

def thread_events_for_thread_id(sysdig_events, thread_id):
    return [x for x in sysdig_events if x.thread_id==thread_id]


def _distinct_thread_ids(sysdig_events):
    return list(set([o.thread_id for o in sysdig_events]))
