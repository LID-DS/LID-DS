import secrets
import time
from concurrent.futures.thread import ThreadPoolExecutor
from threading import Thread
from typing import Dict, Optional

from docker.models.containers import Container

from lid_ds.core.collector.collector import Collector
from lid_ds.core.image import ChainImage
from lid_ds.utils.docker_utils import format_command, get_ip_address
from lid_ds.core.objects.base import ScenarioContainerBase
from lid_ds.sim.dockerize import run_image, show_logs
from lid_ds.utils import log


class ScenarioNormal(ScenarioContainerBase):
    def __init__(self, image: ChainImage, wait_times):
        super().__init__(image)
        self.wait_times = wait_times
        self.containers: Dict[str, Optional[Container]] = dict(
            (secrets.token_hex(8), None) for _ in range(len(wait_times)))
        self.logger = {}
        self.teardown_flag = False
        self.thread_pool = ThreadPoolExecutor(max_workers=len(wait_times) + 1)
        if self.to_stdin:
            self.log_threads = []

    def start_containers(self):
        for k in self.containers.keys():
            args = format_command(self.image.init_args)
            self.containers[k] = run_image(self.image.name, network=self.network, name=k, command=args)
            self.logger[k] = log.get_logger(f"[NORMAL] {k}", self.queue)
            Collector().add_container(k, "normal", get_ip_address(self.containers[k]))

    def start_simulation(self):
        for i, name in enumerate(self.containers):
            if self.to_stdin:
                t = Thread(target=show_logs, args=(self.containers[name], self.logger[name]))
                t.start()
                self.log_threads.append(t)
            self.thread_pool.submit(self._simulate_container, self.wait_times[i], name)
        return dict(zip(self.containers.keys(), self.wait_times))

    def teardown(self):
        for _, container in self.containers.items():
            container.remove(force=True)
        for t in self.log_threads:
            t.join()
        self.teardown_flag = True
        self.thread_pool.shutdown(wait=True)

    def _simulate_container(self, wait_times, name):
        socket = None
        if self.to_stdin:
            socket = self.containers[name].attach_socket(params={'stdin': 1, 'stream': 1})
            socket._writing = True
        for wt in wait_times:
            # split up sleeping to prevent long waiting times after automatic exploit-end-detection
            # breaks execution after teardown_flag=True
            # granularity = 10ms
            for i in range(int(wt/0.01)):
                time.sleep(0.01)
                if self.teardown_flag:
                    return None

            for command in self.image.commands:
                cmd = format_command(command.command)
                if command.stdin:
                    try:
                        socket.write(cmd.encode() + b"\n")
                    except:
                        pass
                else:
                    _, out = self.containers[name].exec_run(cmd)
                    for line in out.decode("utf-8").split("\n")[:-1]:
                        self.logger[name].info("%s" % line)
