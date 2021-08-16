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
            "time": {"exploit": []},
            "container": [],
        }
        self.name = None
        self.logger = log.get_logger("collector", ScenarioEnvironment().logging_queue)
        self.container_ready = None

    def _calculate_time_value(self, value=None, source=None) -> dict:
        if value is None:
            value = time()
            source = "CONTROL_SCRIPT"
        if source is None:
            source = "UNKNOWN"

        time_store = self.storage["time"]
        if "warmup_end" not in time_store:
            return {
                "absolute": float(value),
                "relative": 0,
                "source": source,
            }
        else:
            return {
                "absolute": float(value),
                "relative": float(value) - time_store["warmup_end"]["absolute"],
                "source": source
            }

    def set_meta(self, name, image, recording_time, is_exploit, exploit_name):
        self.name = name
        self.storage["image"] = image
        # recording time = -1 -> auto detection of exploit end and autostop of recording
        self.storage["recording_time"] = recording_time if not recording_time == -1 else 'auto-detected'
        self.storage["exploit"] = is_exploit
        self.storage["exploit_name"] = exploit_name

    def set_container_ready(self):
        self.container_ready = self._calculate_time_value()['absolute']

    def set_warmup_end(self):
        self.storage["time"]["warmup_end"] = self._calculate_time_value()
        self.storage["time"]["container_ready"] = self._calculate_time_value(self.container_ready, "CONTROL_SCRIPT")

    def add_container(self, name, role, ip):
        self.storage['container'].append({'name': name, 'role': role, 'ip': ip})

    def set_exploit_time(self, name, value=None, source=None):
        for i, entry in enumerate(self.storage["time"]["exploit"]):
            if entry['name'] is name:
                # only update if value is set
                if value is not None:
                    self.logger.info(f"Optimized attack time for {name} from {entry['absolute']} to {value} from {source}")
                    self.storage["time"]["exploit"][i] = {**self._calculate_time_value(value, source), 'name': name}
                return
        self.storage["time"]["exploit"].append({**self._calculate_time_value(value, source), 'name': name})

    def set_recording_time(self, start_time, end_time):
        recording_time = end_time - start_time
        self.storage['recording_time'] = int(recording_time.total_seconds())

    @property
    def attacker_ip(self):
        for container in self.storage['container']:
            if container['role'] == 'attacker':
                return container['ip']

    def write(self, storage_services: List[CollectorStorageService]):
        for service in storage_services:
            service.store_dict(self.name, self.storage)




