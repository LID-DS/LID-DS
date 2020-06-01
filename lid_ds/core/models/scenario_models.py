import secrets
from abc import ABC
from concurrent.futures.thread import ThreadPoolExecutor
import time
from threading import Thread
from typing import Union, Optional, Dict

from docker.models.containers import Container

from lid_ds.core.collector.collector import Collector
from lid_ds.core.models.environment import ScenarioEnvironment, format_command
from lid_ds.helpers.names_generator import scenario_name
from lid_ds.sim.behaviour import get_sampling_method
from lid_ds.sim.dockerize import run_image, show_logs
from lid_ds.utils import log


class ScenarioContainerBase(ABC):
    def __init__(self):
        self.queue = ScenarioEnvironment().logging_queue
        self.network = ScenarioEnvironment().network


class ScenarioGeneralMeta:
    def __init__(self, exploit_time: Union[int, float], warmup_time: Union[int, float],
                 recording_time: Union[int, float]):
        if not isinstance(warmup_time, (int, float)):
            raise TypeError("Warmup time needs to be an integer or float")
        if not isinstance(recording_time, (int, float)):
            raise TypeError("Recording time needs to be an integer or float")
        if not isinstance(exploit_time, (int, float)):
            raise TypeError(
                "Exploit start time needs to be an integer or float")
        if exploit_time > recording_time:
            raise ValueError(
                "The start time of the exploit must be before the end of the recording!"
            )
        self.name = scenario_name(self)
        self.exploit_time = exploit_time
        self.is_exploit = exploit_time is not 0
        self.warmup_time = warmup_time
        self.recording_time = recording_time


class ScenarioNormalMeta(ScenarioContainerBase):
    def __init__(self, image_name, behaviour_type, user_count, command, run_command="", to_stdin=False):
        super().__init__()
        self.image_name = image_name
        self.behaviour_type = behaviour_type  # TODO: make enum
        self.command = command
        self.to_stdin = to_stdin
        self.run_command = run_command
        self.containers: Dict[str, Optional[Container]] = dict(
            ("normal_%s" % secrets.token_hex(8), None) for _ in range(user_count))
        self.wait_times = []
        self.thread_pool = ThreadPoolExecutor(max_workers=user_count + 1)
        if to_stdin:
            self.log_threads = []

    def generate_behaviours(self, recording_time):
        self.wait_times = get_sampling_method(self.behaviour_type).generate_wait_times(len(self.containers),
                                                                                       recording_time)

    def start_containers(self):
        for k in self.containers.keys():
            args = format_command(self.run_command)
            self.containers[k] = run_image(self.image_name, network=self.network, name=k, command=args)

    def start_simulation(self):
        logger = log.get_logger("control_script", self.queue)
        logger.debug("Simulating with %s" % dict(zip(self.containers.keys(), self.wait_times)))
        for i, name in enumerate(self.containers):
            if self.to_stdin:
                t = Thread(target=show_logs, args=(self.containers[name], name, self.queue))
                t.start()
                self.log_threads.append(t)
            self.thread_pool.submit(self._simulate_container, self.wait_times[i], name)

    def teardown(self):
        for _, container in self.containers.items():
            container.remove(force=True)
        for t in self.log_threads:
            t.join()
        self.thread_pool.shutdown(wait=True)

    def _simulate_container(self, wait_times, name):
        if self.to_stdin:
            socket = self.containers[name].attach_socket(params={'stdin': 1, 'stream': 1})
            socket._writing = True
            for wt in wait_times:
                time.sleep(wt)
                try:
                    socket.write(self.command.encode() + b"\n")
                except:
                    pass
        else:
            for wt in wait_times:
                time.sleep(wt)
                _, out = self.containers[name].exec_run(self.command)
                for line in out.decode("utf-8").split("\n")[:-1]:
                    print("[%s]: %s" % (name, line))


class ScenarioExploitMeta(ScenarioContainerBase):
    def __init__(self, image_name, command, to_stdin=False):
        super().__init__()
        self.image_name = image_name
        self.container = None
        self.container_name = "attacker_%s" % secrets.token_hex(8)
        self.logger = log.get_logger(self.container_name, self.queue)
        self.command = command
        self.to_stdin = to_stdin

    def start_container(self):
        self.container = run_image(self.image_name, self.network, self.container_name)

    def execute_exploit_at_time(self, execution_time):
        while time.time() < execution_time:
            time.sleep(0.5)
        Collector().set_exploit_start()

        self.logger.info('Executing the exploit now at {}'.format(time.time()))
        command = format_command(self.command)
        if self.to_stdin:
            socket = self.container.attach_socket(params={'stdin': 1, 'stream': 1})
            socket._writing = True
            socket.write(command.encode() + b"\n")
        else:
            _, logs = self.container.exec_run(command)
            print(logs)
        Collector().set_exploit_end()

    def teardown(self):
        self.container.stop()