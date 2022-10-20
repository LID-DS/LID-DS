"""
The purpose of the Scenario module is to provide the scenario class.
The scenario class should give a libraryuser the ability to simply
create new scenarios and implementing needed functions.
"""
import datetime
import random
from abc import ABCMeta, abstractmethod
from threading import Thread
from time import sleep, time
from typing import List

import docker
from docker.errors import NotFound

from lid_ds.core.collector.collector import Collector, CollectorStorageService
from lid_ds.core.objects.victim import ScenarioVictim, RecordingModes
from lid_ds.utils import log
from .image import ChainImage
from .objects.attacker import ScenarioAttacker
from .objects.environment import ScenarioEnvironment
from .objects.meta import ScenarioMeta
from .objects.normal import ScenarioNormal
from ..postprocessing import postprocessing


class Scenario(metaclass=ABCMeta):
    @abstractmethod
    def wait_for_availability(self, container):
        """
        Implement a hook that returns once the container is ready
        """

    @abstractmethod
    def init_victim(self, container, logger):
        """
        Implement a method for initialising the victim container, pass if this is not needed
        """

    @property
    def is_exploit(self):
        return self.general_meta.is_exploit

    """
    The scenario class provides a baseclass to derive from
    in order to implement a custom security scenario
    """

    def __init__(
            self,
            victim: ChainImage,
            normal: ChainImage,
            exploit: ChainImage,
            wait_times,
            warmup_time=60,
            recording_time=300,
            exploit_start_time=0,
            exploit_name='default',
            storage_services: List[CollectorStorageService] = None,
            recording_mode=RecordingModes.Sysdig
    ):
        """
        initialize all time sequences needed for the recording process
        as well es for statistically relevant execution
        """
        self.general_meta = ScenarioMeta(exploit_start_time,
                                         warmup_time,
                                         recording_time,
                                         exploit_name)
        self.logger = log.get_logger("control_script", ScenarioEnvironment().logging_queue)
        self.logging_thread = Thread(target=log.print_logs)
        self.logging_thread.start()

        self.storage_services = storage_services if storage_services else []

        self.victim = ScenarioVictim(victim)
        self.normal = ScenarioNormal(normal, wait_times)
        self.exploit = ScenarioAttacker(exploit)

        self.auto_stop_recording = True if recording_time == -1 else False

        self._recording_mode = recording_mode

        if exploit_start_time == 0 and self.auto_stop_recording:
            raise ValueError("Autostop of recording is only possible with active exploit")

        Collector().set_meta(
            name=self.general_meta.name,
            image=victim.name,
            recording_time=self.general_meta.recording_time,
            is_exploit=self.general_meta.is_exploit,
            exploit_name=self.general_meta.exploit_name
        )

    def _container_init(self):
        self.logger.info(f"Starting normal container")
        self.normal.start_containers()
        if self.is_exploit:
            self.logger.info("Starting exploit container")
            self.exploit.start_container()

    def _warmup(self):
        self.logger.info('Warming up Scenario: {}'.format(self.general_meta.name))
        sleep(self.general_meta.warmup_time)
        Collector().set_warmup_end()

        if self.is_exploit:
            exploit_time = time() + self.general_meta.exploit_time
            self.exploit_thread = Thread(
                target=self.exploit.execute_exploit_at_time, args=(exploit_time,))
            self.exploit_thread.start()

        self.logger.info('Start Normal Behaviours for Scenario: {}'.format(self.general_meta.name))
        wts = self.normal.start_simulation()
        self.logger.debug("Simulating with %s" % wts)

    def _recording(self):
        self.logger.info('Start Recording Scenario: {}'.format(self.general_meta.name))
        with self.victim.record_container(mode=self._recording_mode) as (sysdig, tcpdump, resource):
            if self.auto_stop_recording:
                self.start_time = datetime.datetime.now()
                exploit_container_id = self.exploit.container.attrs['Id']
                while True:
                    client = docker.from_env()
                    if client.containers.get(exploit_container_id).attrs['State']['Running']:
                        sleep(0.1)
                    else:
                        sleep_time = random.randint(5, 15)
                        self.logger.info(f"attack finished - stopping recording in {sleep_time} seconds")
                        sleep(sleep_time)
                        break
                self.end_time = datetime.datetime.now()
            else:
                sleep(self.general_meta.recording_time)

    def _postprocessing(self):
        if self.is_exploit:
            postprocessing.optimize_attack_time(self.exploit.image)
        Collector().write(self.storage_services)

    def _teardown(self):
        try:
            if self.is_exploit and not self.auto_stop_recording:
                self.exploit.teardown()
        except NotFound:
            self.logger.info('Attacker already shut down')

        self.normal.teardown()
        ScenarioEnvironment().network.remove()

    def __call__(self):
        try:
            self._container_init()
            self.logger.info('Simulating Scenario: {}'.format(self))
            with self.victim.start_container(self.wait_for_availability,
                                             self.init_victim) as container:
                Collector().set_container_ready()
                self._warmup()
                self._recording()
        finally:
            self._teardown()

        if self.auto_stop_recording:
            Collector().set_recording_time(self.start_time, self.end_time)

        self._postprocessing()

        log.stop()
        self.logging_thread.join()

    def __repr__(self):
        if self.general_meta.is_exploit:
            return '<{} {} recording_time={} warmup_time={} exploit_start_time={}>'.format(
                self.__class__.__name__,
                self.general_meta.name,
                self.general_meta.recording_time,
                self.general_meta.warmup_time,
                self.general_meta.exploit_time
            )
        return '<{} {} recording_time={} warmup_time={}>'.format(
            self.__class__.__name__,
            self.general_meta.name,
            self.general_meta.recording_time,
            self.general_meta.warmup_time,
        )
