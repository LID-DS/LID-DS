import sched, time, secrets
from enum import Enum

from lid_ds.sim import gen_schedule_wait_times, sampler
from abc import ABC, abstractmethod
from typing import List

# TODO: rename 

# meta class for all sampling types
# enum that maps class to string
# call them for creation of wait times

class SamplingStrategy(ABC):
    @abstractmethod
    def generate_wait_times(self, user_count, duration) -> List[List[float]]:
        pass


class GeneratedSampling(SamplingStrategy):
    def generate_wait_times(self, user_count, duration):
        wait_times: List[List[float]] = []
        for _ in range(user_count):
            wait_times.append(gen_schedule_wait_times(duration))
        return wait_times


def get_sampling_method(type) -> SamplingStrategy:
    return GeneratedSampling()


class Sampler(Enum):
    GENERAL = GeneratedSampling()


class ContainerBehaviour(ABC):
    normal_behaviour: (str, List[str])
    @abstractmethod
    def _init_normal(self):
        pass

class Behaviour:
    def __init__(self, actions, total_duration):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.actions = actions
        self.wait_times = gen_schedule_wait_times(total_duration)

    def __call__(self, *args, **kwargs):
        if len(self.actions) == len(self.wait_times):
            for i in range(len(min([self.actions, self.wait_times], key=len))):
                time.sleep(self.wait_times[i])
                self.actions[i]()


class GeneratedBehaviour:
    def __init__(self, actions, total_duration):
        self.sample = sampler.generate_sample_real_data(total_duration)
        self.actions = actions
        self.wait_times = sampler.convert_sample_to_wait_times(self.sample)
        self.name = secrets.token_hex(8)
        sampler.visualize_sample(self.sample, total_duration)

    # TODO: outsource to _base.py
    def __call__(self, *args, **kwargs):
        if len(self.actions) == len(self.wait_times):
            for i in range(len(min([self.actions, self.wait_times], key=len))):
                time.sleep(self.wait_times[i])
                self.actions[i]()
