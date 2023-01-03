import random
from pprint import pprint

from algorithms.building_block import BuildingBlock
from algorithms.building_block_manager import BuildingBlockManager
from algorithms.decision_engines.ae import AE, AEMode
from algorithms.decision_engines.lstm import LSTM
from algorithms.decision_engines.som import Som
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.flags import Flags
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.persistance import save_to_mongo
from algorithms.util.dependency_graph_encoding import dependency_graph_to_config_tree
from dataloader.direction import Direction


def stub_fake_results_in_mongo_db():
    """
    Creates fake experiment result in the mongo db used for testing purposes.
    """
    lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019",
        "LID-DS-2021"
    ]
    # scenarios ordered by training data size asc
    # 0 - 14
    scenario_names = [
        "CVE-2017-7529",
        "CVE-2014-0160",
        "CVE-2012-2122",
        "Bruteforce_CWE-307",
        "CVE-2020-23839",
        "CWE-89-SQL-injection",
        "PHP_CWE-434",
        "ZipSlip",
        "CVE-2018-3760",
        "CVE-2020-9484",
        "EPS_CWE-434",
        "CVE-2019-5418",
        "Juice-Shop",
        "CVE-2020-13942",
        "CVE-2017-12635_6"
    ]
    ###################
    # feature config:
    epochs = 10
    size = 10
    scenario_range = scenario_names

    for scenario_number in range(0, len(scenario_range)):
        for thread_aware in [True, False]:
            for ngram_length in [3, 5, 7]:
                algos = gen_decision_engines(epochs, ngram_length, size, thread_aware)
                for direction in Direction:
                    for algo in algos:
                        decider = MaxScoreThreshold(algo)
                        building_block_manager = BuildingBlockManager(decider)
                        dg = building_block_manager.get_dependency_graph()
                        config_tree = dependency_graph_to_config_tree(dg)

                        results = {
                            "false_positives": random.randint(0, 100),
                            "true_positives": random.randint(0, 1000),
                            "true_negatives": random.randint(0, 100000),
                            "false_negatives": random.randint(0, 10000),
                            "correct_alarm_count": random.randint(0, 100),
                            "exploit_count": random.uniform(0, 1),
                            "detection_rate": random.uniform(0, 1),
                            "consecutive_false_positives_normal": random.uniform(0, 1),
                            "consecutive_false_positives_exploits": random.uniform(0, 1),
                            "recall": random.uniform(0, 1),
                            "precision_with_cfa": random.uniform(0, 1),
                            "precision_with_syscalls": random.uniform(0, 1),
                            "f1_cfa": random.uniform(0, 1)
                        }
                        if False:
                            pprint(results)

                        # enrich results with configuration and save to disk
                        results['algorithm'] = algo.name
                        results['config'] = config_tree
                        results['scenario'] = scenario_range[scenario_number]
                        results['dataset'] = lid_ds_version[lid_ds_version_number]
                        results['direction'] = direction.name.lower()

                        save_to_mongo(results, db_name='experiments_test')


def gen_decision_engines(epochs, ngram_length, size, thread_aware) -> list[BuildingBlock]:
    w2v_epochs = epochs * random.randint(5, 25)
    w2v_size = size * random.randint(1, 4)
    batch_size = size * random.randint(1, 20)
    som_size = size * random.randint(1, 20)

    ng_w2v_int_name = Ngram(
        [W2VEmbedding(IntEmbedding(), w2v_size, ngram_length, w2v_epochs)],
        thread_aware,
        ngram_length,
    )

    ngram_w2v_int_flags = Ngram(
        [W2VEmbedding(IntEmbedding(Flags()), w2v_size, ngram_length, w2v_epochs)],
        thread_aware,
        ngram_length,
    )
    ngram_complex = Ngram(
        [
            W2VEmbedding(IntEmbedding(ProcessName()), w2v_size, ngram_length, w2v_epochs),
            ReturnValue(),
            TimeDelta(thread_aware),
        ],
        thread_aware,
        ngram_length + 1
    )
    ngram_int = Ngram(
        [IntEmbedding()],
        thread_aware,
        ngram_length,
    )
    concat = Concat([ngram_int, ngram_complex])

    return [
        AE(IntEmbedding(), AEMode.LOSS),
        Som(ngram_complex, epochs, size=som_size),
        Som(ng_w2v_int_name, epochs, size=som_size),
        Som(ngram_int, epochs, size=som_size),
        Som(concat, epochs, size=som_size),
        Som(ngram_w2v_int_flags, size=som_size),
        LSTM(
            ng_w2v_int_name,
            40,
            input_dim=20,
            batch_size=batch_size,
            epochs=epochs,
            model_path="Model/f-asj/LSTM/ag-29dd-True.model"
        ),
        LSTM(ngram_int, 40, input_dim=20, epochs=epochs),
        LSTM(ngram_complex, 40, input_dim=20, epochs=epochs),
        LSTM(concat, 40, input_dim=20, epochs=epochs),
        Stide(ngram_int),
        Stide(IntEmbedding())
    ]


if __name__ == "__main__":
    stub_fake_results_in_mongo_db()
