import json
import os
import pymongo

from lid_ds.core.collector.collector import CollectorStorageService


class MongoDBStorage(CollectorStorageService):
    def __init__(self, db_name, host="localhost", port=27017, username=None, password=None):
        print("Checking MongoDB Connection: {}:{}".format(host, port))
        user_pw = ("{}:{}@" if username and password else "{}@" if username else "").format(username, password)
        self.client = pymongo.MongoClient("mongodb://{}{}:{}/".format(user_pw, host, port))
        self.client.server_info()
        self.db = self.client[db_name]

    def store_dict(self, name: str, obj: dict):
        dict.update({"_id": name})
        self.db["runs"].insert(dict)

    def __del__(self):
        self.client.close()

