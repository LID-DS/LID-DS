import multiprocessing
import secrets
from concurrent.futures.thread import ThreadPoolExecutor
from contextlib import contextmanager
import time
from threading import Thread
from typing import Union, Optional, Dict

from docker.models.containers import Container

from lid_ds.helpers import wait_until
from lid_ds.helpers.names_generator import scenario_name
from lid_ds.sim.behaviour import get_sampling_method
from lid_ds.sim.dockerize import run_image, show_logs, create_network
from lid_ds.utils import log


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


class ScenarioNormalMeta:
    def __init__(self, image_name, behaviour_type, user_count, command, run_command="", to_stdin=False):

        self.image_name = image_name
        self.behaviour_type = behaviour_type  # TODO: make enum
        self.command = command
        self.to_stdin = to_stdin
        self.run_command = run_command
        self.containers: Dict[str, Optional[Container]] = dict(
            ("normal_%s" % secrets.token_hex(8), None) for _ in range(user_count))
        self.wait_times = []
        if to_stdin:
            self.log_processes = []

    def generate_behaviours(self, recording_time):
        self.wait_times = get_sampling_method(self.behaviour_type).generate_wait_times(len(self.containers),
                                                                                       recording_time)

    def start_containers(self, network):
        for k in self.containers.keys():
            self.containers[k] = run_image(self.image_name, network=network, name=k, command=self.run_command)

    def stop_containers(self):
        for _, container in self.containers.items():
            container.remove(force=True)
        for p in self.log_processes:
            p.join()

    def _simulate_container(self, wait_times, name):
        if self.to_stdin:
            socket = self.containers[name].attach_socket(params={'stdin': 1, 'stream': 1})
            socket._writing = True
            for wt in wait_times:
                time.sleep(wt)
                try:
                    socket.write(self.command.encode() + b"\n")
                except Exception as e:
                    print("EXP:", e)
        else:
            for wt in wait_times:
                time.sleep(wt)
                _, out = self.containers[name].exec_run(self.command)
                for line in out.decode("utf-8").split("\n")[:-1]:
                    print("[%s]: %s" % (name, line))

    def start_simulation(self, thread_pool, queue):
        logger = log.get_logger("control_script", queue)
        logger.debug("Simulating with %s" % dict(zip(self.containers.keys(), self.wait_times)))
        for i, name in enumerate(self.containers):
            if self.to_stdin:
                p = multiprocessing.Process(target=show_logs, args=(self.containers[name], name, queue))
                p.start()
                self.log_processes.append(p)
            thread_pool.submit(self._simulate_container, self.wait_times[i], name)


class ScenarioExploitMeta:
    def __init__(self, image_name, command, to_stdin=False):
        self.image_name = image_name
        self.container = None
        self.command = command
        self.to_stdin = to_stdin

    def start_container(self, network):
        container_name = "attacker_%s" % secrets.token_hex(8)
        self.container = run_image(self.image_name, network, container_name)

    def execute_exploit_at_time(self, time):
        if self.to_stdin:
            socket = self.container.attach_socket(params={'stdin': 1, 'stream': 1})
            socket._writing = True
            # for wt in wait_times:
            #    time.sleep(wt)
            #    try:
            #        socket.write(self.command.encode() + b"\n")
            #    except Exception as e:
            #        print("EXP:", e)
        else:
            pass
            # for wt in wait_times:
            #    time.sleep(wt)
            #    _, out = self.containers[name].exec_run(self.command)
            #    for line in out.decode("utf-8").split("\n")[:-1]:
            #        print("[%s]: %s" % (name, line))

    def stop_container(self):
        self.container.stop()


class ScenarioVictimMeta:
    def __init__(self, image_name, port_mapping, queue):
        self.image_name = image_name
        self.port_mapping = port_mapping
        self.queue = queue

    @contextmanager
    def start_container(self, network, check_if_available, init=None):
        name = "victim"  # TODO: enable parallelize
        logger = log.get_logger(name, self.queue)
        container = run_image(self.image_name, network, name, self.port_mapping)
        logger.debug("Waiting for container to be available")
        wait_until(check_if_available, 60, 1, container=container)
        logger.info("Container available on port(s) %s" % self.port_mapping)
        if init is not None:
            init()
        yield container
        container.stop()


class ScenarioEnvironment:
    def __init__(self, name, user_count):
        self.network = create_network(name)
        self.log_thread_pool = ThreadPoolExecutor(max_workers=user_count + 1)
        self.execution_thread_pool = ThreadPoolExecutor(max_workers=user_count + 1)
        self.logging_lock = multiprocessing.RLock()
        self.logging_queue = multiprocessing.Queue(-1)
