"""
Demonstrates the usage of the experiment result query
"""

from tabulate import tabulate

from algorithms.evaluation.experiment_result_queries import ResultQuery
from dataloader.direction import Direction


def find_results_with_specific_config():
    """ Find all results matching the specified algorithm, dataset and configurations

    config aliases should be given for each algorithm containing a dictionary that represents the dependency graph.

    Given a dependency graph that look like:

    >>> from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
    >>> from algorithms.decision_engines.lstm import LSTM
    >>> from algorithms.features.impl.ngram import Ngram
    >>> from algorithms.features.impl.int_embedding import IntEmbedding
    >>>
    >>> int_embedding = IntEmbedding()
    >>> ngram = Ngram(thread_aware=True, feature_list=[int_embedding], ngram_length=10)
    >>> lstm = LSTM(input_vector=ngram, distinct_syscalls=10, input_dim=20, hidden_layers=10)
    >>> final_bb = MaxScoreThreshold(feature=lstm)

    The following `config_aliases` extract the config values of `LSTM.hidden_layers`, `Ngram.thread_aware` and `Ngram.ngram_length`.
    This values can later be used in the `where` clause.

    Note:
        - `input` in the config aliases dictionary can be called what ever you want (feauture_list, input_vector, ...) as long as the value is a list of dictionaries.
        - If there are config parameters with the same name in different features you can give them a different aliase. See the next more complex example below.
        - Intembedding as an implicit dependency of `SyscallName`. Eventhough we do not specify it in the featurelist it will be included in the results. To prevent this you can set `features_exact_match=True` in the query
    """
    lstm_config_aliases = {
        "LSTM": {
            "name": "MaxScoreThreshold",
            "input": [
                {
                    "name": "LSTM",
                    "hidden_layers": "hidden_layers",
                    "input": [
                        {
                            "name": "Ngram",
                            "thread_aware": "thread_aware",
                            "ngram_length": "ngram_length"
                        }
                    ],
                },
            ],
        },
    }
    lstm_features = {
        "LSTM": ["MaxScoreThreshold", "LSTM", "Ngram", "IntEmbedding"],
    }
    where = {
        "ngram_length": 10,
        "$and": [
            {"false_positives": {"$lt": 50}},
            {"false_positives": {"$gt": 5}}
        ]
    }

    results = ResultQuery(collection_name="experiments_test").find_results(
        algorithms=["LSTM"],
        scenarios=["CVE-2017-7529", "CVE-2014-0160"],
        directions=[Direction.BOTH],
        features=lstm_features,
        features_exact_match=False,
        config_aliases=lstm_config_aliases,
        where=where
    )

    print(tabulate(results, headers="keys", tablefmt="github"))


# The features and configurations bellow will be used in all following examples and demonstrate a more complex usage.

features = {
    "Som": ["MaxScoreThreshold", "Som", "Concat", "Ngram", "IntEmbedding"],
    "LSTM": ["MaxScoreThreshold", "LSTM", "Ngram", "W2VEmbedding"],
}

config_aliases = {
    "Som": {
        "name": "MaxScoreThreshold",
        "input": [
            {
                "name": "Som",
                "epochs": "som_epochs",
                "sigma": "sigma",
                "size": "som_size",
                "input": [
                    {
                        "name": "Concat",
                        "input": [
                            {
                                "name": "Ngram",
                                "thread_aware": "thread_aware",
                                "ngram_length": "concat_1_ng_len",
                            },
                            {
                                "name": "Ngram",
                                "ngram_length": "concat_2_ng_len",
                                "input": [
                                    {
                                        "name": "W2VEmbedding",
                                        "vector_size": "concat_2_w2v_size",
                                    },
                                    {
                                        "name": "ReturnValue",
                                        "min_max_scaling": "rv_minmax"
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        ],
    },
    "LSTM": {
        "name": "MaxScoreThreshold",
        "input": [
            {
                "name": "LSTM",
                "batch_size": "lstm_batch_size",
                "epochs": "epochs",
                "input": [
                    {
                        "name": "Ngram",
                        "thread_aware": "thread_aware",
                    }
                ],
            },
        ],
    },
}


def find_best_algorithm():
    """
    Finds the best algorithm given some features sorted by average DR
    """
    results = ResultQuery(collection_name="experiments_test").find_best_algorithm(
        algorithms=["Som", "LSTM"],
        scenarios=["CVE-2017-7529", "CVE-2014-0160"],
        directions=[Direction.BOTH],
        features=features,
        config_aliases=config_aliases,
    )

    print(tabulate(results, headers="keys", tablefmt="github"))


def algorithm_wise_best_average_configuration():
    """
    Algorithm wise best average configuration over given scenario and features
    """
    results = ResultQuery(collection_name="experiments_test").algorithm_wise_best_average(
        algorithms=["Som", "LSTM"],
        scenarios=["CVE-2017-7529", "CVE-2014-0160"],
        directions=[Direction.BOTH],
        features=features,
        config_aliases=config_aliases,
        firstK_in_group=3
    )

    for result in results:
        print(result['_id'])
        print(tabulate(result['results'], headers="keys", tablefmt="github"))


def scenario_wise_best_average_configuration():
    """
    For each scenario get the best algorithm and configuration
    """
    results = ResultQuery(collection_name="experiments_test").scenario_wise_best_configuration(
        algorithms=["Som", "LSTM", "AE", "Stide"],
        directions=[Direction.OPEN, Direction.BOTH],
        features=features,
        config_aliases=config_aliases,
        firstK_in_group=3
    )
    results = [r for result in results for r in result['results']]
    print(tabulate(results, headers="keys", tablefmt="github"))


if __name__ == '__main__':
    print("########## find results with specific configuration ##########")
    find_results_with_specific_config()

    print("########## best algorithm ##########")
    find_best_algorithm()

    print("########## algo wise best configuration ##########")
    algorithm_wise_best_average_configuration()

    print("########## scenario wise best configuration ##########")
    scenario_wise_best_average_configuration()
