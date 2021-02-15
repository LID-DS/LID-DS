import json
import os

from lid_ds.core.collector.collector import CollectorStorageService
from lid_ds.core.objects.environment import ScenarioEnvironment


class JSONFileStorage(CollectorStorageService):
    def __init__(self, filename="runs.json"):
        self.file = open(os.path.join(ScenarioEnvironment().out_dir, filename), "a+")

    def store_dict(self, name: str, obj: dict):
        self.file.seek(0)
        try:
            data = json.load(self.file)
        except json.JSONDecodeError:
            data = {}

        data.update({name: obj})
        self.file.seek(0)
        self.file.truncate()
        json.dump(data, self.file, indent=4, sort_keys=True)

    def __del__(self):
        self.file.close()

