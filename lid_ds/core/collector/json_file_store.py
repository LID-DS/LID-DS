import json
import os

from lid_ds.core.collector.collector import CollectorStorageService


class JSONFileStore(CollectorStorageService):
    def __init__(self):
        out_dir = os.environ.get("LIDDS_OUT_DIR", ".")
        self.file = open(os.path.join(out_dir, "runs.json"), "a+")

    def store_dict(self, name: str, dict: dict):
        self.file.seek(0)
        try:
            data = json.load(self.file)
        except json.JSONDecodeError:
            data = {}

        data.update({name: dict})
        self.file.seek(0)
        self.file.truncate()
        json.dump(data, self.file, indent=4, sort_keys=True)

    def __del__(self):
        self.file.close()

