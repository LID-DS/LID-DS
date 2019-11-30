import json
from random import random
from time import time

class Collector:
    def __init__(self, name):
        self.storage = {}
        self.name = name
        self.file = open("runs.json", "a+")

    def set_exploit_time(self, time):
        self.storage["exploit_start"] = time

    def __del__(self):
        self.file.seek(0)
        try:
            data = json.load(self.file)
        except json.JSONDecodeError:
            data = {}

        data.update({self.name: self.storage})
        self.file.seek(0)
        self.file.truncate()
        json.dump(data, self.file)
        self.file.close()


if __name__ == '__main__':
    c = Collector("run_{}".format(time()))
    c.set_exploit_time(random())