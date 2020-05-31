from contextlib import contextmanager
from lid_ds.sim.dockerize import show_logs
from threading import Thread
import docker
import os

client = docker.from_env()


@contextmanager
def run_tcpdump(run_name, victim):
    dir = os.path.abspath(os.getcwd())
    container = client.containers.run("itsthenetwork/alpine-tcpdump",
                                      volumes={dir: {'bind': '/capture', 'mode': 'rw'}}, name="tcpdump",
                                      network="container:%s" % victim.name, privileged=True,
                                      command="-i any -U -s0 -w /capture/%s.pcap" % run_name, remove=True, detach=True)
    for line in container.logs(stream=True):
        if b"tcpdump:" in line:
            break
    print("[tcpdump]: Writing tcpdump to %s.pcap" % run_name)
    yield container
    container.kill()
