import multiprocessing
import secrets

import docker

from lid_ds.helpers import scenario_name
from lid_ds.utils.singleton import Singleton

client = docker.from_env()


@Singleton
class ScenarioEnvironment:
    def __init__(self):
        self.victim_hostname = "victim_%s" % secrets.token_hex(8)
        self.recording_name = scenario_name(self)
        self.network = client.networks.create("network_%s" % self.recording_name)
        self.logging_queue = multiprocessing.Queue(-1)
