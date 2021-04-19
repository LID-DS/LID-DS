import secrets
import time
from threading import Thread

from lid_ds.core.collector.collector import Collector
from lid_ds.core.image import Image, ChainImage
from lid_ds.utils.docker_utils import format_command, get_ip_address
from lid_ds.core.objects.base import ScenarioContainerBase
from lid_ds.sim.dockerize import run_image, show_logs
from lid_ds.utils import log


class ScenarioAttacker(ScenarioContainerBase):
    def __init__(self, image: ChainImage):
        super().__init__(image)
        self.container = None
        self.container_name = secrets.token_hex(8)
        self.logger = log.get_logger(f"[ATTACKER] {self.container_name}", self.queue)
        self.logging_thread = None

    def start_container(self):
        args = format_command(self.image.init_args)
        self.container = run_image(self.image.name, network=self.network, name=self.container_name, command=args)
        Collector().add_container(self.container_name, "attacker", get_ip_address(self.container))
        if self.to_stdin:
            self.logging_thread = Thread(target=show_logs, args=(self.container, self.logger))
            self.logging_thread.start()

    def execute_exploit_at_time(self, execution_time):
        while time.time() < execution_time:
            time.sleep(0.5)

        for command in self.image.commands:
            self.logger.info('Executing the exploit step %s now at %s' % (command.name, time.time()))
            Collector().set_exploit_time(command.name)
            cmd = format_command(command.command)
            if self.to_stdin:
                socket = self.container.attach_socket(params={'stdin': 1, 'stream': 1})
                socket._writing = True
                try:
                    socket.write(cmd.encode() + b"\n")
                except:
                    pass
            else:
                _, out = self.container.exec_run(cmd)
                for line in out.decode("utf-8").split("\n")[:-1]:
                    self.logger.info(line)

    def teardown(self):
        self.container.stop()
        if self.logging_thread:
            self.logging_thread.join()
