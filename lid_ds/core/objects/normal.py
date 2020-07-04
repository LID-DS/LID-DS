import secrets
import time
from concurrent.futures.thread import ThreadPoolExecutor
from threading import Thread
from typing import Dict, Optional

from docker.models.containers import Container

from lid_ds.core.image import StdinCommand, Image
from lid_ds.utils.docker_utils import format_command
from lid_ds.core.objects.base import ScenarioContainerBase
from lid_ds.sim.behaviour import get_sampling_method
from lid_ds.sim.dockerize import run_image, show_logs
from lid_ds.utils import log


class ScenarioNormalMeta(ScenarioContainerBase):
    def __init__(self, image: Image, behaviour_type, user_count):
        super().__init__(image)
        self.behaviour_type = behaviour_type  # TODO: make enum
        self.containers: Dict[str, Optional[Container]] = dict(
            ("normal_%s" % secrets.token_hex(8), None) for _ in range(user_count))
        self.wait_times = []
        self.thread_pool = ThreadPoolExecutor(max_workers=user_count + 1)
        if self.to_stdin:
            self.log_threads = []

    def generate_behaviours(self, recording_time):
        self.wait_times = get_sampling_method(self.behaviour_type).generate_wait_times(len(self.containers),
                                                                                       recording_time)

    def start_containers(self):
        for k in self.containers.keys():
            args = format_command(self.image.init_args)
            self.containers[k] = run_image(self.image.name, network=self.network, name=k, command=args)

    def start_simulation(self):
        for i, name in enumerate(self.containers):
            if self.to_stdin:
                t = Thread(target=show_logs, args=(self.containers[name], name, self.queue))
                t.start()
                self.log_threads.append(t)
            self.thread_pool.submit(self._simulate_container, self.wait_times[i], name)
        return dict(zip(self.containers.keys(), self.wait_times))

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
                    socket.write(self.image.command.command.encode() + b"\n")
                except:
                    pass
        else:
            for wt in wait_times:
                time.sleep(wt)
                _, out = self.containers[name].exec_run(self.image.command)
                for line in out.decode("utf-8").split("\n")[:-1]:
                    print("[%s]: %s" % (name, line))
