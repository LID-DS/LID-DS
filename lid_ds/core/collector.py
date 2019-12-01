import json
import os
from time import time


class Collector:
    def __init__(self, name, image, recording_time, is_exploit):
        self.storage = {
            "image": image,
            "recording_time": recording_time,
            "exploit": is_exploit,
            "time": {}
        }
        self.name = name
        out_dir = os.environ.get("LIDDS_OUT_DIR", ".")
        self.file = open(os.path.join(out_dir, "runs.json"), "a+")

    def __set_time_value(self, key: str):
        t = time()
        time_store = self.storage["time"]
        if key is "container_ready":
            time_store[key] = {
                "absolute": int(t),
                "relative": 0
            }
        elif time_store["container_ready"] is None:
            raise CollectorError("Set container_ready for relative time")
        else:
            time_store[key] = {
                "absolute": int(t),
                "relative": int(t) - time_store["container_ready"]["absolute"]
            }

    def set_exploit_start(self):
        self.__set_time_value("exploit_start")

    def set_exploit_end(self):
        self.__set_time_value("exploit_end")

    def set_container_ready(self):
        self.__set_time_value("container_ready")

    def set_warmup_end(self):
        self.__set_time_value("warmup_end")

    def __del__(self):
        self.file.seek(0)
        try:
            data = json.load(self.file)
        except json.JSONDecodeError:
            data = {}

        data.update({self.name: self.storage})
        self.file.seek(0)
        self.file.truncate()
        json.dump(data, self.file, indent=4, sort_keys=True)
        self.file.close()


class CollectorError(Exception):
    def __init__(self, message):
        self.message = message
