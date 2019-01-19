"""
The parse_scap module provides useful functions
for interacting with and reading from sysdig scap
files
"""
import subprocess, os
from lid_ds.data_models import SysdigEvent
from lid_ds.analysis.analyze_sysdig_events import thread_events
from lid_ds.analysis.analyze_syscalls import _find_end_of_system_call_event
from lid_ds.data_models import SysCall

def parse_scap(rel_path):
    path = os.path.abspath(rel_path)
    sysdig_events = []
    for line in get_syscall_by_syscall(path):
        sysdig_events.append(handle_line(line))

    syscalls = []
    for thread_id, events in thread_events(sysdig_events):
        for event in events:
            if event.enter_event:
                syscall = _find_end_of_system_call_event(event, events)
                if syscall != None:
                    syscalls.append(syscall)

    syscalls_sorted = sorted(syscalls, key=lambda x: x.start_timestamp)
    return syscalls_sorted

def get_syscall_by_syscall(path):
    if os.path.exists(path) and path.endswith('scap'):
        p = subprocess.Popen('sysdig -r {}'.format(path).split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while(True):
            # returns None while subprocess is running
            retcode = p.poll()
            line = p.stdout.readline()
            yield line
            if retcode is not None:
                break
    else:
        raise FileNotFoundError('Path does not exist or is not a valid recording!')

def handle_line(line):
    return SysdigEvent(line)
