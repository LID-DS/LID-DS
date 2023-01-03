"""
queries for gathering experiment results from the MongoDB
"""
import itertools
import os
from typing import Union

from pymongo import MongoClient
from pymongo.collection import Collection

from dataloader.direction import Direction


class ResultQuery:
    """
        Queries for gathering experiment results from the MongoDB.
        For usage see examples in :py:mod:`algorithms.evaluation.example_queries.py`
    """

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
    ) -> list[dict]:
        """
            Find all results matching the specified algorithm, dataset and configurations
        Args:
            algorithms: algorithms to include
            scenarios: scenarios to include
            datasets: datasets to include
            directions: directions to include
            features: keys of dict are algorithm names and values is list of feature names.
                order of features should reflect how they are processed
            features_exact_match: if true: there should only be the specified features. If false: algo should start with specified features.
            config_aliases: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases
            where: dictionary containing a MongoDB `$match <https://www.mongodb.com/docs/v6.0/reference/operator/aggregation/match/>`__
                or `query <https://www.mongodb.com/docs/v6.0/tutorial/query-documents/>`__ expression for further filtering results

        Returns:
            list[dict]: found experiment results

        """
        pipeline = _pipeline(
            match_base(algorithms, datasets, directions, features, features_exact_match, scenarios),
            addFields_stage(config_aliases),
            {"$match": where or {}},
            {"$project": {"config": 0, "_id": 0}}
        )
        results = list(self._experiments.aggregate(pipeline))
        return results

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
            sort_by: dict[str, int] = None,
    ) -> list[dict]:
        """ Get all results matching the specified arguments sorted
        Args:
            algorithms: algorithms to include
            scenarios: scenarios to include
            datasets: datasets to include
            directions: directions to include
            features: keys of dict are algorithm names and values is list of feature names.
                order of features should reflect how they are processed
            features_exact_match: if true: there should only be the specified features. If false: algo should start with specified features.
            group_by: group by for aggregating metrics. Default is ["datasets", "algorithms"]
            config_aliases: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases
            sort_by:  dictionary containing a MongoDB `$sort <https://www.mongodb.com/docs/manual/reference/operator/aggregation/sort/>`__
                expression for sorting results at the end. Default is sort by avg_DR (DESC) and avg_FA (ASC) = {"avg_DR": -1, "avg_FA": 1 }

        Returns:
            list[dict]: sorted experiment results
        """
        if group_by is None:
            group_by = ["dataset", "algorithm"]

        pipeline = _pipeline(
            match_base(algorithms, datasets, directions, features, features_exact_match, scenarios),
            addFields_stage(config_aliases),
            grouped_metrics_aggregate(group_by, config_aliases),
            {"$sort": sort_by or {"avg_DR": -1, "avg_FA": 1}}
        )
        results = list(self._experiments.aggregate(pipeline))
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
            firstK_in_group: int = 3,
            where: dict = None,
            sort_by=None
    ) -> list[dict]:
        """ For each algorithm, find the top k configurations

        Args:
            algorithms: algorithms to include
            scenarios: scenarios to include
            datasets: datasets to include
            directions: directions to include
            features: keys of dict are algorithm names and values is list of feature names.
                order of features should reflect how they are processed
            features_exact_match: if true: there should only be the specified features. If false: algo should start with specified features.
            group_by: group by for aggregating metrics. Default is ["datasets", "algorithms"]
            config_aliases: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases
            firstK_in_group: limit results in a group (per algorithm)
            where: dictionary containing a MongoDB `$match <https://www.mongodb.com/docs/v6.0/reference/operator/aggregation/match/>`__
                or `query <https://www.mongodb.com/docs/v6.0/tutorial/query-documents/>`__ expression for further filtering results
            sort_by:  dictionary containing a MongoDB `$sort <https://www.mongodb.com/docs/manual/reference/operator/aggregation/sort/>`__
                expression for sorting results at the end. Default is sort by avg_DR (DESC) and avg_FA (ASC) = {"avg_DR": -1, "avg_FA": 1 }

        Returns:
            list[dict]: list of groups of sorted results in the following format:

                >>> [
                >>> {
                >>>     "_id": { "dataset": "LID-DS-2019", "algorithm": "Som" },
                >>>     "results": [
                >>>         {"dataset": "LID-DS-2019", "algorithm": "Som", "epochs": 100, "thread_aware": True, "avg_DR": 0.99, "avg_FA": 10},
                >>>         {"dataset": "LID-DS-2019", "algorithm": "Som", "epochs": 200, "thread_aware": True, "avg_DR": 0.89, "avg_FA": 1},
                >>>         {"dataset": "LID-DS-2019", "algorithm": "Som", "epochs": 300, "thread_aware": True, "avg_DR": 0.89, "avg_FA": 20},
                >>>     ]
                >>> },
                >>> {
                >>>     "_id": { "dataset": "LID-DS-2019", "algorithm": "LSTM" },
                >>>     "results": [
                >>>         {"dataset": "LID-DS-2019", "algorithm": "LSTM", "epochs": 200, "thread_aware": True, "avg_DR": 0.99, "avg_FA": 10},
                >>>         {"dataset": "LID-DS-2019", "algorithm": "LSTM", "epochs": 100, "thread_aware": True, "avg_DR": 0.80, "avg_FA": 12},
                >>>         {"dataset": "LID-DS-2019", "algorithm": "LSTM", "epochs": 300, "thread_aware": True, "avg_DR": 0.30, "avg_FA": 2},
                >>>     ]
                >>> }

        """
        if group_by is None:
            group_by = ["dataset", "algorithm"]

        pipeline = _pipeline(
            match_base(algorithms, datasets, directions, features, features_exact_match, scenarios),
            addFields_stage(config_aliases),
            {"$match": where or {}},
            grouped_metrics_aggregate(group_by, config_aliases),
            regroup_and_sort(group_by, firstK_in_group, sort_by)
        )
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
            sort_by=None
    ) -> list[dict[str, dict]]:
        """ For each scenario, find the top k algorithms
        Args:
            algorithms: algorithms to include
            scenarios: scenarios to include
            datasets: datasets to include
            directions: directions to include
            features: keys of dict are algorithm names and values is list of feature names.
                order of features should reflect how they are processed
            features_exact_match: if true: there should only be the specified features. If false: algo should start with specified features.
            group_by: group by for aggregating metrics. Default is ["datasets", "scenario" ]
            config_aliases: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases
            firstK_in_group: limit results in a group (per scenario)
            where: dictionary containing a MongoDB `$match <https://www.mongodb.com/docs/v6.0/reference/operator/aggregation/match/>`__
                or `query <https://www.mongodb.com/docs/v6.0/tutorial/query-documents/>`__ expression for further filtering results
            sort_by:  dictionary containing a MongoDB `$sort <https://www.mongodb.com/docs/manual/reference/operator/aggregation/sort/>`__
                expression for sorting results at the end. Default is sort by avg_DR (DESC) and avg_FA (ASC) { "a

        Returns:
            list[dict]: list of grouped results. each dictionary in the returned list contains an `_id` and `results` field.
                `_id` is a dictionary containing the `group_by` keys.
                `results` is a list òf the results

                Results are in the following format:

                >>> [
                >>> {
                >>>     "_id": { "dataset": "LID-DS-2019", "scenario": "CVE-2017-2122" },
                >>>     "results": [
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2017-2122","algorithm": "Som", "epochs": 100, "thread_aware": True, "avg_DR": 0.99, "avg_FA": 10},
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2017-2122","algorithm": "LSTM", "epochs": 200, "thread_aware": True, "avg_DR": 0.89, "avg_FA": 1},
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2017-2122","algorithm": "Som", "epochs": 300, "thread_aware": True, "avg_DR": 0.89, "avg_FA": 20},
                >>>     ]
                >>> },
                >>> {
                >>>     "_id": { "dataset": "LID-DS-2019", "scenario": "CVE-2020-9484"},
                >>>     "results": [
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2020-9484","algorithm": "LSTM", "epochs": 200, "thread_aware": True, "avg_DR": 0.99, "avg_FA": 10},
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2020-9484","algorithm": "Som", "epochs": 100, "thread_aware": True, "avg_DR": 0.80, "avg_FA": 12},
                >>>         {"dataset": "LID-DS-2019","scenario": "CVE-2020-9484","algorithm": "LSTM", "epochs": 300, "thread_aware": True, "avg_DR": 0.30, "avg_FA": 2},
                >>>     ]
                >>> }
        """
        if group_by is None:
            group_by = ["dataset", "scenario"]

        pipeline = _pipeline(
            match_base(algorithms, datasets, directions, features, features_exact_match, scenarios),
            addFields_stage(config_aliases),
            {"$match": where or {}},
            grouped_metrics_aggregate(group_by + ["algorithm"], config_aliases),
            regroup_and_sort(group_by, firstK_in_group, sort_by)
        )
        result = list(self._experiments.aggregate(pipeline))
        return result


def _pipeline(*args: Union[list[dict], dict]):
    result = []
    for stage in args:
        if isinstance(stage, list):
            result += stage
        elif isinstance(stage, dict):
            result += [stage]
        else:
            raise TypeError(f"pipeline stage of type {type(stage)} not supported")

    return result


def match_base(
        algorithms: list[str],
        datasets: list[str],
        directions: list[Direction],
        features: dict[str, list[str]],
        features_exact_match: bool,
        scenarios
) -> dict:
    """Constructs the $match stage dictionary for filtering results

    **MongoDB**: `$match <https://www.mongodb.com/docs/v6.0/reference/operator/aggregation/match/>`__ filters the
    documents to pass only the documents that match the specified condition(s) to the next pipeline stage.

    This filter will often be used as a first stage in the pipeline. It only reduces the number of results and does
    not change the shape of the documents.

    Args:
        algorithms: list of algorithms
        datasets: list of dataset names
        directions: list of Direction enum
        features: keys of dict are algorithm names and values is list of feature names.
            order of features should reflect how they are processed
        features_exact_match: if true: there should only be the specified features. If false: algo should start with specified features.
        scenarios: list of scenario names

    Returns:
        dict: match stage dictionary containing the specified queries

        The dict has the following format

        >>> {
        >>>   "algorithm": { "$in": [ "LSTM" ] },
        >>>   "scenario": { "$in": [ "CVE-2017-7529", "CVE-2014-0160" ] },
        >>>   "direction": { "$in": [ "open" ] },
        >>>   "$expr": {
        >>>     "$function": {
        >>>       "body": "/** MongoDB custom function to query experiments by features **/ function has_features([...]",
        >>>       "args": [ "$config.nodes", "$config.links", "$algorithm", { "LSTM": [ "MaxScoreThreshold", "LSTM", "Ngram", "W2VEmbedding" ] }, False ],
        >>>       "lang": "js"
        >>>     }
        >>>   }
        >>> }

    """
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
    return {"$match": match}


def addFields_stage(config_aliases_dict: dict[str, dict]) -> dict:
    """ Construct $addFields stage dictionary for extracting configuration values

    **MongoDB**: `$addFields <https://www.mongodb.com/docs/manual/reference/operator/aggregation/addFields/>`__
    outputs documents that contain all existing fields from the input documents and newly added fields.

    This stage allows filtering/aggregating by config values in following stages. It first extracts the config keys
    and aliases from the dictionary `aliases`. These are used to extract the config values from the results and added
    as new fields on the top level of a result document.

    Args:
        config_aliases_dict: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases

    Returns:
        dict: addFields stage dictionary
        list[tuple]: config key and alias pairs

    Examples:
        The alias parameter should have the following format

        >>> conf_aliases = {
        >>>     "Som": {
        >>>         "name": "MaxScoreThreshold",
        >>>         "input": [{
        >>>             "name" : "Som",
        >>>             "epochs": "som_epochs",
        >>>             "input": [{
        >>>                 "name": "Ngram",
        >>>                 "thread_aware": "thread_aware",
        >>>             }]
        >>>         }]
        >>>     },
        >>>     "LSTM": {
        >>>         "name": "MaxScoreThreshold",
        >>>         "input": [{
        >>>             "name": "LSTM",
        >>>             "epochs": "lstm_epochs",
        >>>         }]
        >>>     }
        >>> }
        >>> addFields_query, config_aliases_keys = addFields_stage(conf_aliases)
        >>> print(config_aliases_keys)
        >>> [("epochs", "som_epochs"), ("thread_aware", "thread_aware"), ("epochs", "lstm_epochs")]

    """

    config_aliases = extract_config_aliases(config_aliases_dict)
    addFields = {}
    for config, config_alias in config_aliases:
        addFields[config_alias] = {
            "$function": {
                "body": _custom_js_function("get_config_value"),
                "args": ["$config.nodes", "$config.links", "$algorithm", config_aliases_dict, config_alias],
                "lang": "js"
            }
        }
    return {"$addFields": addFields}


def grouped_metrics_aggregate(group_by: list[str], config_aliases_dict: dict[str, dict] = None) -> list[dict]:
    """ Construct $group stage to calculate average detection rate, false alarms,...

    **MongoDB**: `$group <https://www.mongodb.com/docs/manual/reference/operator/aggregation/group/>`__
    stage separates documents into groups according to a "group key". The output is one document for each unique group key.
    The operation returns documents in the format:

    >>> [
    >>> {
    >>>     "dataset" : "LID-DS-2019",
    >>>     "algorithm" : "Som",
    >>>     "som_epoch": 100,
    >>>     "avg_DR": 0.98,
    >>>     "avg_FA": 11.3,
    >>>     "count": 10,
    >>> },
    >>> {
    >>>     "dataset" : "LID-DS-2019",
    >>>     "algorithm" : "Som",
    >>>     "som_epoch": 200,
    >>>     "avg_DR": 0.99,
    >>>     "avg_FA": 12.4,
    >>>     "count": 10,
    >>> }
    >>> ...

    Args:
        group_by: base keys to group results, default is dataset and algorithm
        config_aliases_dict: config aliases to group results

    Returns:
        query dict for grouping stage

    """
    # grouping phase
    group_by = {key: f"${key}" for key in group_by}

    if config_aliases_dict:
        config_aliases = extract_config_aliases(config_aliases_dict)
        group_by |= {alias: f"${alias}" for _, alias in config_aliases}

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
    # flatten results to simplify subsequent processing
    group_by_ids = {key: f"$_id.{key}" for key in group_by} | {key: f"${key}" for key in group} | {"_id": False}
    return [{"$group": group}, {"$project": group_by_ids}]


def regroup_and_sort(group_by: list[str], firstK_in_group: int, sort_by: dict[str, int] = None) -> list[dict]:
    """ Construct a $group and a $project with $sortArray stage to sort already grouped results.

    **MongoDB**: `$group <https://www.mongodb.com/docs/manual/reference/operator/aggregation/group/>`__
    stage separates documents into groups according to a "group key". The output is one document for each unique group key.
    Used here to regroup the results.

    This can be used after another grouping phase (for example calculation of the metrics avg_DR, avg_FA ...)
    to sort the results algorithm- , scenario-, or some config-wise.

    Args:
        group_by: list of keys to group
        firstK_in_group: limit the number of results per group.
        sort_by: dict key are sorting keys. value 1 is ASC, -1 is DESC. Default is {"avg_DR": -1, "avg_FA": 1 }

    Returns:
        list[dict] group and project stage dictionaries

    Examples:
        Given the following results after the stage :func:`~grouped_aggregate_metrics_stage`

        >>> [
        >>> {
        >>>     "dataset" : "LID-DS-2019",
        >>>     "algorithm" : "Som",
        >>>     "som_epoch": 100,
        >>>     "avg_DR": 0.98,
        >>>     "avg_FA": 11.3,
        >>>     "count": 10,
        >>> },
        >>> {
        >>>     "dataset" : "LID-DS-2019",
        >>>     "algorithm" : "Som",
        >>>     "som_epoch": 200,
        >>>     "avg_DR": 0.99,
        >>>     "avg_FA": 12.4,
        >>>     "count": 10,
        >>> }
        >>> {
        >>>     "dataset" : "LID-DS-2019",
        >>>     "algorithm" : "LSTM",
        >>>     "lstm_epoch": 300,
        >>>     "avg_DR": 0.99,
        >>>     "avg_FA": 12.4,
        >>>     "count": 10,
        >>> }
        >>> ...

        and group_by = ["dataset", "algorithm"]. This stage will first regroup them so that:

        >>> [
        >>>   {
        >>>    "_id": { "dataset" : "LID-DS-2019",  "algorithm" : "Som" }
        >>>    "results": [
        >>>       {
        >>>           "dataset" : "LID-DS-2019",
        >>>           "algorithm" : "Som",
        >>>           "som_epoch": 200,
        >>>           "avg_DR": 0.99,
        >>>           "avg_FA": 12.4,
        >>>           "count": 10,
        >>>       },
        >>>       {
        >>>           "dataset" : "LID-DS-2019",
        >>>           "algorithm" : "Som",
        >>>           "som_epoch": 100,
        >>>           "avg_DR": 0.98,
        >>>           "avg_FA": 11.3,
        >>>           "count": 10,
        >>>       },
        >>>      ]
        >>>   },{
        >>>    "_id": { "dataset" : "LID-DS-2019",  "algorithm" : "LSTM" }
        >>>    "results": [
        >>>       {
        >>>        "dataset" : "LID-DS-2019",
        >>>        "algorithm" : "LSTM",
        >>>        "lstm_epoch": 300,
        >>>        "avg_DR": 0.99,
        >>>        "avg_FA": 12.4,
        >>>        "count": 10,
        >>>    }
        >>> ...
        >>>    ]
        >>> }

        After that, the list in `results` will be sorted

    """
    #
    group_by_ids = {key: f"${key}" for key in group_by}
    group = {
        "_id": group_by_ids,
        "results": {
            "$push": "$$ROOT"
        }
    }

    sort_group = {
        "_id": "$_id",
        "results": {
            "$slice": [
                {
                    "$sortArray": {
                        "input": "$results",
                        "sortBy": sort_by or {
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

    return [{"$group": group}, {"$project": sort_group}]


def extract_config_aliases(aliases: dict[str, dict]) -> list[tuple[str, str]]:
    """

    Args:
        aliases: dictionary in the structure of the dependency graph containing algorithm, config keys and aliases

    Returns:
        list[tuple]: config key and alias pairs

    Examples:
        The alias parameter should have the following format

        >>> conf_aliases = {
        >>>     "Som": {
        >>>         "name": "MaxScoreThreshold",
        >>>         "input": [{
        >>>             "name" : "Som",
        >>>             "epochs": "som_epochs",
        >>>             "input": [{
        >>>                 "name": "Ngram",
        >>>                 "thread_aware": "thread_aware",
        >>>             }]
        >>>         }]
        >>>     },
        >>>     "LSTM": {
        >>>         "name": "MaxScoreThreshold",
        >>>         "input": [{
        >>>             "name": "LSTM",
        >>>             "epochs": "lstm_epochs",
        >>>         }]
        >>>     }
        >>> }
        >>> config_aliases_keys = extract_config_aliases(conf_aliases)
        >>> print(config_aliases_keys)
        >>> [("epochs", "som_epochs"), ("thread_aware", "thread_aware"), ("epochs", "lstm_epochs")]
    """

    config_aliases = [_get_config_aliases([config]) for config in aliases.values()]
    config_aliases = list(itertools.chain.from_iterable(config_aliases))
    return config_aliases


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
            if key == "name":
                continue
            if _is_leaf(alias):
                leaves.append((key, alias))
            else:
                leaves += _get_config_aliases(alias)
    return leaves
