"""
queries for gathering best results in DB
"""
import itertools
import os

from pymongo import MongoClient
from pymongo.collection import Collection

from dataloader.direction import Direction


class ResultQuery:
    def __init__(self, collection_name="experiments"):
        mongo_ip = os.environ["LID_DS_MONGO_IP"]
        mongo_user = os.environ["LID_DS_MONGO_USER"]
        mongo_pw = os.environ["LID_DS_MONGO_PW"]

        client = MongoClient(
            mongo_ip,
            username=mongo_user,
            password=mongo_pw
        )

        self._experiments: Collection = client[collection_name][collection_name]

    def find_results(
            self,
            algorithms: list[str],
            scenarios: list[str] = None,
            datasets: list[str] = None,
            directions: list[Direction] = None,
            features: dict[str, list[str]] = None,
            features_exact_match: bool = False,
            config_aliases: dict[str, dict] = None,
            where: dict = None,
    ):
        """ Find all results matching the specified algorithm, dataset and configurations """
        match = self.construct_match_stage(algorithms, datasets, directions, features, features_exact_match, scenarios)
        addFields, config_aliases_keys = self.construct_addFields_stage(config_aliases)

        # final pipeline
        pipeline = [
            {"$match": match},
            {"$addFields": addFields},
            {"$match": where},
            {"$project": {"config": 0, "_id": 0}}
        ]
        return list(self._experiments.aggregate(pipeline))

    def find_best_algorithm(
            self,
            algorithms: list[str],
            scenarios: list[str] = None,
            datasets: list[str] = None,
            directions: list[Direction] = None,
            features: dict[str, list[str]] = None,
            features_exact_match: bool = False,
            group_by: list[str] = None,
            config_aliases: dict = None,
    ):
        """ Get all results matching the specified arguments.
        TODO:
        Args:
            algorithms:
            scenarios:
            datasets:
            directions:
            features:
            features_exact_match:
            group_by:
            config_aliases:
        """

        match = self.construct_match_stage(algorithms, datasets, directions, features, features_exact_match, scenarios)
        addFields, config_aliases_keys = self.construct_addFields_stage(config_aliases)

        group = ResultQuery.aggregate_metrics(group_by, config_aliases_keys)
        # sorting phase
        sort = {
            "avg_DR": -1,
            "avg_FA": 1
        }

        # final pipeline
        pipeline = [
            {"$match": match},
            {"$addFields": addFields},
            {"$group": group},
            {"$sort": sort}
        ]
        results = list(self._experiments.aggregate(pipeline))
        results = [r.pop("_id") | r for r in results]
        return results

    def algorithm_wise_best_average(
            self,
            algorithms: list[str],
            scenarios: list[str] = None,
            datasets: list[str] = None,
            directions: list[Direction] = None,
            features: dict[str, list[str]] = None,
            features_exact_match: bool = False,
            group_by: list[str] = None,
            config_aliases: dict = None,
            firstK_in_group: int = None,
            where: dict = None,
    ):
        """
            For each algorithm, find the k best configurations
        TODO:
        Args:
            algorithms:
            scenarios:
            datasets:
            directions:
            features:
            features_exact_match:
            group_by:
            config_aliases:
            firstK_in_group:
            where:
        """
        match = self.construct_match_stage(algorithms, datasets, directions, features, features_exact_match, scenarios)
        addFields, config_aliases_keys = self.construct_addFields_stage(config_aliases)
        group = ResultQuery.aggregate_metrics(group_by, config_aliases_keys)

        push_groups_to_root = {
            "_id": {
                "dataset": "$_id.dataset",
                "algorithm": "$_id.algorithm"
            },
            "results": {
                "$push": "$$ROOT"
            }
        }

        sort_algo_wise = {
            "_id": "$_id",
            "results": {
                "$slice": [
                    {
                        "$sortArray": {
                            "input": "$results",
                            "sortBy": {
                                "avg_F1": -1,
                                "avg_DR": -1,
                                "avg_FA": 1
                            }
                        }
                    },
                    0,
                    firstK_in_group
                ]
            }
        }

        # final pipeline
        pipeline = [
            {"$match": match},
            {"$addFields": addFields},
            {"$match": where or {}},
            {"$group": group},
            {"$group": push_groups_to_root},
            {"$project": sort_algo_wise},
        ]
        result = list(self._experiments.aggregate(pipeline))
        return result

    def scenario_wise_best_configuration(
            self,
            algorithms: list[str] = None,
            scenarios: list[str] = None,
            datasets: list[str] = None,
            directions: list[Direction] = None,
            features: dict[str, list[str]] = None,
            features_exact_match: bool = False,
            group_by: list[str] = None,
            config_aliases: dict = None,
            firstK_in_group: int = 3,
            where: dict = None,
    ):
        """
            For each scenario, find the k best algorithms
        TODO:
        Args:
            algorithms:
            scenarios:
            datasets:
            directions:
            features:
            features_exact_match:
            group_by:
            config_aliases:
            firstK_in_group:
            where:
        """
        match = self.construct_match_stage(algorithms, datasets, directions, features, features_exact_match, scenarios)
        addFields, config_aliases_keys = self.construct_addFields_stage(config_aliases)
        if group_by is None:
            group_by = ["dataset", "scenario"]
        group = ResultQuery.aggregate_metrics(group_by, config_aliases_keys)

        # This is helpful for the second grouping. We basically move the result group to the top level of the document.
        push_groups_to_root = {
            "_id": {
                "dataset": "$_id.dataset",
                "scenario": "$_id.scenario",
            },
            "results": {
                "$push": "$$ROOT"
            }
        }

        sort_scenario_wise = {
            "_id": "$_id",
            "results": {
                "$slice": [
                    {
                        "$sortArray": {
                            "input": "$results",
                            "sortBy": {
                                "avg_F1": -1,
                                "avg_DR": -1,
                                "avg_FA": 1
                            }
                        }
                    },
                    0,
                    firstK_in_group
                ]
            }
        }

        # final pipeline
        pipeline = [
            {"$match": match},
            {"$addFields": addFields},
            {"$match": where or {}},
            {"$group": group},
            {"$group": push_groups_to_root},
            {"$project": sort_scenario_wise},
        ]

        result = list(self._experiments.aggregate(pipeline))
        return result

    @staticmethod
    def construct_addFields_stage(aliases) -> tuple[dict, list[tuple]]:
        """ addFields phase to extract config values """
        config_aliases = [_get_config_aliases([config]) for config in aliases.values()]
        config_aliases = list(itertools.chain.from_iterable(config_aliases))
        addFields = {}
        for config, config_alias in config_aliases:
            addFields[config_alias] = {
                "$function": {
                    "body": _custom_js_function("get_config_value"),
                    "args": ["$config.nodes", "$config.links", "$algorithm", aliases, config_alias],
                    "lang": "js"
                }
            }
        return addFields, config_aliases

    @staticmethod
    def construct_match_stage(algorithms, datasets, directions, features, features_exact_match, scenarios) -> dict:
        """ Match phase for filtering results """
        match = {}
        if algorithms is not None:
            match |= {"algorithm": {"$in": algorithms}}
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
        return match

    @staticmethod
    def aggregate_metrics(group_by=None, config_aliases=None) -> dict:
        """
        Group results and calculate average detection rate, false alarms, ...

        Args:
            group_by: base keys to group results, default is dataset and algorithm
            config_aliases: config aliases to group results

        Returns:
            query dict for grouping stage

        """
        # grouping phase
        if group_by is None:
            group_by = {
                "dataset": "$dataset",
                "algorithm": "$algorithm",
            }
        else:
            group_by = {key: f"${key}" for key in group_by}

        if config_aliases:
            group_by |= {alias: f"${alias}" for _, alias in config_aliases}

        # FIXME : make configurable
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
            "avg_F1": {
                "$avg": "$f1_cfa"
            },
            "count": {
                "$sum": 1
            }
        }

        return group


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

    for config in config_groups:
        for key, alias in config.items():
            if key == 'name':
                continue
            if _is_leaf(alias):
                leaves.append((key, alias))
            else:
                leaves += _get_config_aliases(alias)
    return leaves
