"""
The recorder_run module provides a context manager
for the sysdig recording of a container.
"""
import os
import signal
import pexpect
from contextlib import contextmanager


def kill_child(child):
    pid = child.pid
    tries = 0
    while child.isalive():
        tries += 1
        child.sendcontrol('c')
        if tries > 1000:
            break
    if child.isalive():
        os.kill(pid, signal.SIGINT)

@contextmanager
def record_container(container, recording_name, buffer_size=80):
    """
    A context manager managing the sysdig recording
    process for the lifetime of the container
    """
    out_dir = os.environ.get('LIDDS_OUT_DIR', '.')
    sysdig_out_path = os.path.join(out_dir, '{}.scap'.format(recording_name))
    tcp_out_path = os.path.join(out_dir, '{}.pcap'.format(recording_name))
    print('Saving to Sysdig to {}'.format(sysdig_out_path))
    sysdig_child = pexpect.spawn('sysdig -w {} -s {} container.name={} --unbuffered'.format(sysdig_out_path, buffer_size, container.name))
    print('Saving to TCPDump to {}'.format(tcp_out_path))
    tcp_child = pexpect.spawn('tcpdump -i docker0 -w {}'.format(tcp_out_path))
    yield sysdig_child, tcp_child
    kill_child(tcp_child)
    kill_child(sysdig_child)
