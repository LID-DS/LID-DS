from lid_ds.data_models import SysCall

def _find_end_of_system_call_event(event, events):
    events_sorted = sorted(events, key=lambda x: x.event_time)
    index_of_event = events_sorted.index(event)

    for event_tentative in events_sorted[index_of_event:]:
        if event_tentative.event_type == event.event_type and event.enter_event and not event_tentative.enter_event and event.process == event_tentative.process and event.executing_cpu == event_tentative.executing_cpu:
            syscall = SysCall(event, event_tentative)
            return syscall

    return None
