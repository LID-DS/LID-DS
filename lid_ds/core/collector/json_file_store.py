import json
import os

from lid_ds.core.collector.collector import CollectorStorageService
from lid_ds.core.objects.environment import ScenarioEnvironment


class JSONFileStorage(CollectorStorageService):
    def __init__(self):
        self.file = None

    def store_dict(self, name: str, obj: dict):
        self.file = open(os.path.join(ScenarioEnvironment().out_dir, name + '.json'), "a+")
        json.dump(obj, self.file, indent=4, sort_keys=True)

    def __del__(self):
        self.file.close()

