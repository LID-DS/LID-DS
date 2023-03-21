from statistics import mean

import matplotlib
from matplotlib import pyplot as plt
from tabulate import tabulate

from algorithms.evaluation.experiment_result_queries import ResultQuery
from dataloader.direction import Direction

font = {
    'weight': 'bold',
    'size': 12
}

matplotlib.rc('font', **font)
plt.style.use('bmh')

config_aliases = {
    "Stide": {
        "name": "MaxScoreThreshold",
        "input": [{
            "name": "StreamSum",
            "input": [{
                "name": "Stide",
                "input": [{
                    "name": "Ngram",
                    "ngram_length": "ngram",
                }],
            }],
        }],
    },
}

config_aliases_entropy = {
    "Stide": {
        "name": "NgramEntropy",
        "input": [{
            "name": "Ngram",
            "ngram_length": "ngram",
        }],
    },
}


def algorithm_wise_best_average_configuration():
    """
    Algorithm wise best average configuration over given scenario and features
    """

    results = ResultQuery(collection_name="entropy_stide").algorithm_wise_best_average(
        algorithms=["Stide"],
        # group_by=["algorithm", "scenario", "dataset"],
        group_by=["algorithm"],
        directions=[Direction.BOTH],
        config_aliases=config_aliases,
        firstK_in_group=3
    )

    for result in results:
        print(result['_id'])
        print(tabulate(result['results'], headers="keys", tablefmt="github"))


def results_with_lowest_entropy():
    results = ResultQuery(collection_name="entropy").group_by_and_sort(
        group_by=["scenario", "dataset"],
        sort_by={"entropy_train_val": 1},
    )

    lowest_entropies_ngram = {}
    for result in results:
        conf = result['_id']['scenario'], result['_id']['dataset']
        lowest_entropies_ngram[conf] = result['results'][0]['ngram_length']

    detection_rates = []
    false_alarms = []
    entropie_all = []
    for conf, ng in lowest_entropies_ngram.items():
        scenario, dataset = conf
        results = ResultQuery(collection_name="entropy_stide").find_results(
            datasets=[dataset],
            scenarios=[scenario],
            algorithms=["Stide"],
            config_aliases=config_aliases,
            where={
                "ngram": ng
            }
        )
        if len(results):
            result = results[0]
            detection_rate = result["detection_rate"]
            detection_rates.append(detection_rate)
            false_alarm = result["consecutive_false_positives_normal"] + result["consecutive_false_positives_exploits"]
            false_alarms.append(false_alarm)
            entropie_result = {
                "scenario": scenario,
                "dataset": dataset,
                "ngram": ng,
                "detection_rate": detection_rate,
                "false_alarm": false_alarm
            }
            entropie_all.append(entropie_result)
        else:
            print("No result for", conf, ng)

    print(tabulate(entropie_all, headers="keys", tablefmt="github"))
    print(f"Average DR: {mean(detection_rates)} count: {len(detection_rates)}")
    print(f"Average FA: {mean(false_alarms)}")


if __name__ == '__main__':
    algorithm_wise_best_average_configuration()
    results_with_lowest_entropy()
