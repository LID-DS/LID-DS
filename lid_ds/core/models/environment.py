import multiprocessing
import secrets

import docker
from uuid import uuid4

from lid_ds.utils.singleton import Singleton

client = docker.from_env()


@Singleton
class ScenarioEnvironment:
    def __init__(self):
        self.network = client.networks.create(str(uuid4()))
        self.victim_hostname = "victim_%s" % secrets.token_hex(8)
        self.logging_queue = multiprocessing.Queue(-1)


def format_command(command):
    # TODO: call it first when needed or try to wait for victim
    env = ScenarioEnvironment()
    replaces = {
        'victim': env.victim_hostname,
        'victim_ip': _get_ip_of_container(env.victim_hostname, env.network.name)
    }
    for k, replace in replaces.items():
        command = command.replace("${%s}" % k, replace)
    return command


def _get_ip_of_container(container_name, network_name):
    container = client.containers.get(container_name)
    return container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']