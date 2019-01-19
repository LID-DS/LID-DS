"""
The recorder_run module provides a context manager
for the sysdig recording of a container.
"""
import os
import signal
import pexpect
from contextlib import contextmanager

@contextmanager
def record_container(container, recording_name, buffer_size=80):
    """
    A context manager managing the sysdig recording
    process for the lifetime of the container
    """
    child = pexpect.spawn('sysdig -w {} -s {} container.name={} --unbuffered'.format('/data/' + recording_name + '.scap', buffer_size, container.name))
    yield child
    pid = child.pid
    tries = 0
    while child.isalive():
        tries+=1
        child.sendcontrol('c')
        if tries > 1000:
            break
    if child.isalive():
        os.kill(pid, signal.SIGINT)
