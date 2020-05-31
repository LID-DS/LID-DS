"""
The purpose of the Scenario module is to provide the scenario class.
The scenario class should give a libraryuser the ability to simply
create new scenarios and implementing needed functions.
"""

import logging
import sys

from abc import ABCMeta, abstractmethod
from threading import Thread
from time import sleep, time
from typing import List

from lid_ds.core.collector.collector import Collector, CollectorStorageService
from .models.environment import ScenarioEnvironment
from .models.scenario_models import ScenarioGeneralMeta, ScenarioNormalMeta, ScenarioExploitMeta, ScenarioVictimMeta
from .recorder_run import record_container
from .tcpdump import run_tcpdump
from lid_ds.sim.sampler import visualize
from lid_ds.utils import log


class Scenario(metaclass=ABCMeta):
    @abstractmethod
    def wait_for_availability(self, container):
        """
        Implement a hook that returns once the container is ready
        """

    @abstractmethod
    def init_victim(self):
        """
        Implement a method for initialising the victim container, pass if this is not needed
        """

    """
    The scenario class provides a baseclass to derive from
    in order to implement a custom security scenario
    """

    def __init__(
            self,
            image_name,
            normal_image_name,
            exploit_image_name,
            user_count=10,
            port_mapping={},
            warmup_time=60,
            recording_time=300,
            exploit_start_time=0,
            storage_services: List[CollectorStorageService] = None
    ):
        """
        initialize all time sequences needed for the recording process
        as well es for statistically relevant execution
        """
        self.general_meta = ScenarioGeneralMeta(exploit_start_time, warmup_time, recording_time)
        self.logger = log.get_logger("control_script", ScenarioEnvironment().logging_queue)
        self.logging_thread = Thread(target=log.print_logs)
        self.logging_thread.start()

        self.storage_services = storage_services if storage_services else []

        self.victim_meta = ScenarioVictimMeta(image_name, port_mapping)
        self.normal_meta = ScenarioNormalMeta(normal_image_name, "generated", user_count, command="", to_stdin=True,
                                              run_command="${victim} root 123456")
        self.exploit_meta = ScenarioExploitMeta(exploit_image_name, "sh /app/exploit.sh ${victim_ip}")

        self.logger.info("Generating Behaviours")
        self.normal_meta.generate_behaviours(self.general_meta.recording_time)
        self.logger.info("Starting normal container")
        self.normal_meta.start_containers()
        self.logger.info("Starting exploit container")
        self.exploit_meta.start_container()

        Collector().set_meta(
            name=self.general_meta.name,
            image=self.victim_meta.image_name, recording_time=self.general_meta.recording_time,
            is_exploit=self.general_meta.is_exploit)
        # add_run(self)

    def _container_init(self):
        pass

    def _warmup(self):
        pass

    def _recording(self):
        pass

    def __call__(self, with_exploit=False):
        self.logger.info('Simulating Scenario: {}'.format(self))
        with self.victim_meta.start_container(self.wait_for_availability,
                                              self.init_victim) as container:
            Collector().set_container_ready()
            self.logger.info('Warming up Scenario: {}'.format(self.general_meta.name))
            sleep(self.general_meta.warmup_time)
            Collector().set_warmup_end()

            if self.general_meta.is_exploit:
                exploit_time = time() + self.general_meta.exploit_time
                self.exploit_thread = Thread(
                    target=self.exploit_meta.execute_exploit_at_time, args=(exploit_time,))
                self.exploit_thread.start()

            self.logger.info('Start Normal Behaviours for Scenario: {}'.format(self.general_meta.name))
            self.normal_meta.start_simulation()

            self.logger.info('Start Recording Scenario: {}'.format(self.general_meta.name))
            with record_container(container, self.general_meta.name) as recorder, run_tcpdump(
                    self.general_meta.name, container) as tcpdump:
                sleep(self.general_meta.recording_time)
        self._teardown()

    def _teardown(self):
        Collector().write(self.storage_services)
        self.exploit_meta.teardown()
        self.normal_meta.teardown()
        ScenarioEnvironment().network.remove()
        log.stop()
        self.logging_thread.join()
        # TODO: Remove later
        # visualize(self.general_meta.name)

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
