from abc import ABC, abstractmethod
from time import time
from typing import List

from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.utils import log
from lid_ds.utils.singleton import Singleton


class CollectorStorageService(ABC):
    @abstractmethod
    def store_dict(self, name: str, obj: dict):
        pass


class CollectorError(Exception):
    def __init__(self, message):
        self.message = message


@Singleton
class Collector:
    def __init__(self):
        self.storage = {
            "time": {"exploit": []}
        }
        self.name = None
        self.logger = log.get_logger("collector", ScenarioEnvironment().logging_queue)

    def _calculate_time_value(self, value=None) -> dict:
        t = value if value is not None else time()
        time_store = self.storage["time"]
        if "container_ready" not in time_store:
            return {
                "absolute": int(t),
                "relative": 0
            }
        else:
            return {
                "absolute": int(t),
                "relative": int(t) - time_store["container_ready"]["absolute"]
            }

    def set_meta(self, name, image, recording_time, is_exploit):
        self.name = name
        self.storage["image"] = image
        self.storage["recording_time"] = recording_time
        self.storage["exploit"] = is_exploit

    def set_container_ready(self):
        self.storage["time"]["container_ready"] = self._calculate_time_value()

    def set_warmup_end(self):
        self.storage["time"]["warmup_end"] = self._calculate_time_value()

    def set_exploit_time(self, name, value=None):
        for i, entry in enumerate(self.storage["time"]["exploit"]):
            if entry['name'] is name:
                # only update if value is set
                if value is not None:
                    self.logger.info(f"Optimized attack time for {name} from {entry['absolute']} to {value}")
                    self.storage["time"]["exploit"][i] = {**self._calculate_time_value(value), 'name': name}
                return
        self.storage["time"]["exploit"].append({**self._calculate_time_value(value), 'name': name})

    @property
    def attacker_ip(self):
        return self.storage["attacker"]

    @attacker_ip.setter
    def attacker_ip(self, ip):
        self.storage["attacker"] = ip

    def write(self, storage_services: List[CollectorStorageService]):
        for service in storage_services:
            service.store_dict(self.name, self.storage)




