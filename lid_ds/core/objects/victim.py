import os
import signal
from contextlib import contextmanager
from enum import Enum
from threading import Thread

import pexpect

from lid_ds.core.collector.collector import Collector
from lid_ds.core.image import ChainImage
from lid_ds.core.objects.base import ScenarioContainerBase
from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.helpers import wait_until
from lid_ds.sim.dockerize import run_image
from lid_ds.utils import log
from lid_ds.utils.docker_utils import get_ip_address, get_pid_namespace
from lid_ds.utils.docker_utils import ResourceLoggingThread


def kill_child(child):
    pid = child.pid
    tries = 0
    while child.isalive():
        tries += 1
        child.sendcontrol('c')
        if tries > 1000:
            break
    if child.isalive():
        os.kill(pid, signal.SIGINT)

class RecordingModes(Enum):
    Sysdig = 1
    LTTng = 2


class ScenarioVictim(ScenarioContainerBase):
    def __init__(self, image: ChainImage):
        super().__init__(image)
        self.port_mapping = "all"
        self.container = None
        self.env = ScenarioEnvironment()
        self.logger = log.get_logger(f"[VICTIM] {self.env.victim_hostname}", self.queue)
        self._resource_thread = None

    @contextmanager
    def start_container(self, check_if_available, init=None):
        self.container = run_image(self.image.name, self.env.network, self.env.victim_hostname, self.port_mapping)
        self.logger.debug("Waiting for container to be available")
        self.container.reload()
        Collector().add_container(self.env.victim_hostname, "victim", get_ip_address(self.container))
        wait_until(check_if_available, 60, 1, container=self.container)
        self.logger.info("Container available on port(s) %s" % self.container.ports)
        if init is not None:
            init(self.container, self.logger)
        self._resource_thread = ResourceLoggingThread(self.container)
        self._resource_thread.start()
        yield self.container
        self._resource_thread.stop_it()
        self._resource_thread.join()
        self.container.stop()

    @contextmanager
    def record_container(self, buffer_size=1600, mode=RecordingModes.Sysdig):
        if mode == RecordingModes.Sysdig:
            sysdig = self._sysdig(buffer_size)
            tcpdump = self._tcpdump()
            yield sysdig, tcpdump, self._resource_thread
            kill_child(sysdig)
            tcpdump.kill()
        elif mode == RecordingModes.LTTng:
            lttng = self._lttng()
            tcpdump = self._tcpdump()
            yield lttng, tcpdump, self._resource_thread

            # stop recording
            os.system(f'lttng destroy {self.env.recording_name}')
            tcpdump.kill()




    def _sysdig(self, buffer_size):
        sysdig_out_path = os.path.join(ScenarioEnvironment().out_dir, f'{self.env.recording_name}.scap')
        self.logger.info('Saving to Sysdig to {} with buffer size {}'.format(sysdig_out_path, buffer_size))
        return pexpect.spawn(
            'sysdig -w {} -s {} container.name={} --unbuffered'.format(sysdig_out_path, buffer_size,
                                                                       self.env.victim_hostname))

    def _lttng(self):
        lttng_out_path = os.path.join(ScenarioEnvironment().out_dir, f'{self.env.recording_name}')
        self.logger.info(f'Saving with LTTng to {lttng_out_path}')
        pid_ns = get_pid_namespace(self.container)
        return os.system(
            f'lttng create {self.env.recording_name} --output={lttng_out_path} && ' +
            f'lttng add-context -k -t procname -t pid -t vpid -t tid -t vtid -t pid_ns && ' +
            f'lttng enable-event -k --syscall -a --filter="\\$ctx.pid_ns == {pid_ns}" && ' +
            f'lttng start'
        )


    def _tcpdump(self):
        container = run_image("itsthenetwork/alpine-tcpdump",
                              volumes={os.path.abspath(self.env.out_dir): {'bind': '/capture', 'mode': 'rw'}},
                              name="tcpdump_%s" % self.env.recording_name,
                              network="container:%s" % self.container.name,
                              command="-i any -U -s0 -w /capture/%s.pcap" % self.env.recording_name)
        self.logger.info(
            "Writing tcpdump to %s" % (os.path.join(self.env.out_dir, "%s.pcap" % self.env.recording_name)))
        return container

    def _resource_logger(self):
        pass
