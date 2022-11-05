"""
queries for gathering best results in DB
"""
import os
from pprint import pprint

from pymongo import MongoClient
from pymongo.collection import Collection

from dataloader.direction import Direction


class ResultQuery:
    def __init__(self, collection_name="experiments"):
        mongo_ip = os.environ['LID_DS_MONGO_IP']
        mongo_user = os.environ['LID_DS_MONGO_USER']
        mongo_pw = os.environ['LID_DS_MONGO_PW']

        client = MongoClient(
            mongo_ip,
            username=mongo_user,
            password=mongo_pw
        )

        self._experiments: Collection = client[collection_name][collection_name]

    def get_results(
            self,
            algorithms,
            scenarios: list[str] = None,
            datasets: list[str] = None,
            directions: list[Direction] = None,
            features: dict[str, list[str]] = None,
            features_exact_match=False,
    ):
        """ Get all results matching the specified arguments. """
        match = {"algorithm": {"$in": algorithms}}
        if scenarios is not None:
            match |= {"scenario": {"$in": scenarios}}
        if datasets is not None:
            match |= {"dataset": {"$in": datasets}}
        if directions is not None:
            match |= {"direction": {"$in": [d.value for d in directions]}}

        features_query = {
            "$expr": {
                "$function": {
                    "body": _custom_js_function("has_features"),
                    "args": ["$config.nodes", "$config.links", "$algorithm", features, features_exact_match],
                    "lang": "js"
                }
            }
        }
        match |= features_query

        pipeline = [{
            "$match": match
        }]

        result = list(self._experiments.aggregate(pipeline))

        return result


def _custom_js_function(function_name):
    function_path = os.path.join("js_functions", function_name + ".js")
    with open(function_path, "r") as f:
        return f.read()


def main():
    """ Usage example """
    features = {
        "Som": ["Som", "Ngram", "IntEmbedding"],
        "Stide": ["Stide", "IntEmbedding", ""]
    }
    results = ResultQuery(collection_name="experiments3").get_results(
        algorithms=["Som", "Stide"],
        scenarios=["CVE-2017-7529", "CVE-2014-0160"],
        directions=[Direction.BOTH],
        features=features,
    )

    pprint(results)


if __name__ == '__main__':
    main()
