import multiprocessing
import secrets
import os
import docker

from lid_ds.helpers import scenario_name
from lid_ds.utils.singleton import Singleton

client = docker.from_env()


@Singleton
class ScenarioEnvironment:
    def __init__(self):
        self.victim_hostname = "%s" % secrets.token_hex(8)
        self.recording_name = scenario_name(self)
        self.network = client.networks.create("network_%s" % self.recording_name)
        self.logging_queue = multiprocessing.Queue(-1)
        self.out_dir = os.environ.get('LIDDS_OUT_DIR', './runs')
        if not os.path.exists(self.out_dir):
            os.mkdir(self.out_dir)
