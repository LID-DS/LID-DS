from contextlib import contextmanager
import docker
import os

from lid_ds.core.models.environment import ScenarioEnvironment
from lid_ds.utils import log

client = docker.from_env()


@contextmanager
def run_tcpdump(run_name, victim):
    out_dir = os.path.abspath(os.getcwd())
    container_name = "tcpdump_%s" % run_name
    logger = log.get_logger(container_name, ScenarioEnvironment().logging_queue)
    container = client.containers.run("itsthenetwork/alpine-tcpdump",
                                      volumes={out_dir: {'bind': '/capture', 'mode': 'rw'}}, name=container_name,
                                      network="container:%s" % victim.name, privileged=True,
                                      command="-i any -U -s0 -w /capture/%s.pcap" % run_name, remove=True, detach=True)
    logger.info("Writing tcpdump to %s.pcap" % run_name)
    yield container
    container.kill()
