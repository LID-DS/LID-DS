import json
import os
import pymongo

from lid_ds.core.collector.collector import CollectorStorageService


class MongoDBStore(CollectorStorageService):
    def __init__(self, db_name, host, port):
        self.client = pymongo.MongoClient("mongodb://{}:{}/".format(host, port))
        self.db = self.client[db_name]

    def store_dict(self, name: str, dict: dict):
        dict.update({"_id": name})
        self.db["runs"].insert(dict)

    def __del__(self):
        self.client.close()

