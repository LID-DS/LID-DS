from abc import ABC, abstractmethod
from time import time
from typing import List

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

    def _generate_time_value(self):
        t = time()
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

    def set_exploit_step(self, name):
        self.storage["time"]["exploit"].append({**self._generate_time_value(), 'name': name})

    def set_container_ready(self):
        self.storage["time"]["container_ready"] = self._generate_time_value()

    def set_warmup_end(self):
        self.storage["time"]["warmup_end"] = self._generate_time_value()

    def write(self, storage_services: List[CollectorStorageService]):
        for service in storage_services:
            service.store_dict(self.name, self.storage)




