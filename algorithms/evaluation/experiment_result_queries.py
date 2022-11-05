"""
queries for gathering best results in DB
"""
import itertools
import os

from pymongo import MongoClient
from pymongo.collection import Collection
from tabulate import tabulate

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
            group_by: list[str] = None,
            group_by_config: dict = None,
    ):
        """ Get all results matching the specified arguments. """

        # Match phase for filtering results
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

        # addFields phase to extract config values
        config_aliases = [_get_config_aliases([config]) for config in group_by_config.values()]
        config_aliases = list(itertools.chain.from_iterable(config_aliases))

        addFields = {}
        for config, config_alias in config_aliases:
            addFields[config_alias] = {
                "$function": {
                    "body": _custom_js_function("get_config_value"),
                    "args": ["$config.nodes", "$config.links", "$algorithm", group_by_config, config_alias],
                    "lang": "js"
                }
            }

        # grouping phase
        if group_by is None:
            group_by = {
                'dataset': '$dataset',
                'algorithm': '$algorithm',
            }

        group_by |= {alias: f"${alias}" for _, alias in config_aliases}

        # FIXME: make configurable
        group = {
            "_id": group_by,
            "avg_DR": {
                "$avg": "$detection_rate"
            },
            "avg_FA": {
                "$avg": {
                    "$add": ["$consecutive_false_positives_exploits", "$consecutive_false_positives_normal"]
                }
            },
            "sum_FA": {
                "$sum": {
                    "$add": ["$consecutive_false_positives_exploits", "$consecutive_false_positives_normal"]
                }
            },
            "count": {
                "$sum": 1
            }
        }

        # sorting phase
        sort = {
            "avg_DR": -1,
            "avg_FA": 1
        }

        # final pipeline
        pipeline = [
            {
                "$match": match
            }, {
                "$addFields": addFields
            }, {
                "$group": group
            }, {
                "$sort": sort
            }
        ]
        result = list(self._experiments.aggregate(pipeline))
        result = [r | r.pop("_id") for r in result]

        return result


def _custom_js_function(function_name):
    function_path = os.path.join("js_functions", function_name + ".js")
    with open(function_path, "r") as f:
        return f.read()


def _is_leaf(node):
    return isinstance(node, str)


def _get_config_aliases(config_groups: list[dict]) -> list[tuple[str, str]]:
    """
    Travers "dict tree" and return all leaves
    """
    if len(config_groups) == 0:
        return []
    leaves = []

    for config_group in config_groups:
        for conig in config_group.values():
            for key, alias in conig.items():
                if _is_leaf(alias):
                    leaves.append((key, alias))
                else:
                    leaves += _get_config_aliases(alias)
    return leaves


def main():
    """ Usage example """
    features = {
        "Som": ["Som", "Ngram", "IntEmbedding"],
        "LSTM": ["LSTM", "Ngram", "W2VEmbedding"]
    }
    group_by_config = {
        "Som": {
            "Som": {
                "epochs": "epochs",
                "sigma": "sigma",
                "size": "som_size",
                "input": [
                    {
                        "Ngram": {
                            "ngram_length": "ngram_length",
                        }
                    }
                ],
            }
        },
        "LSTM": {
            "LSTM": {
                "batch_size": "lstm_batch_size",
                "epochs": "epochs",
            }
        }
    }
    results = ResultQuery(collection_name="experiments3").get_results(
        algorithms=["Som", "LSTM"],
        scenarios=["CVE-2017-7529", "CVE-2014-0160"],
        directions=[Direction.BOTH],
        features=features,
        group_by_config=group_by_config,
    )

    print(tabulate(results, headers="keys", tablefmt='github'))


if __name__ == '__main__':
    main()
