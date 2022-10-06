import os
import sys
from pprint import pprint

from algorithms.decision_engines.transformer import Transformer, AnomalyScore
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.ids import IDS
from algorithms.persistance import save_to_json, print_as_table
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    lid_ds_version_number = 1
    scenario_number = 2
    retrain = False
    ngram_length = 11
    anomaly_score = AnomalyScore.MEAN

    batch_size = 256 * 2
    epochs = 10
    thread_aware = True

    lid_ds_version = [
        "LID-DS-2019",
        "LID-DS-2021"
    ]
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
    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError:
            raise ValueError(
                "No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                "$LID_DS_BASE"
            )

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version[lid_ds_version_number]}/{scenario_names[scenario_number]}"

    model_path = f'Models/{lid_ds_version[lid_ds_version_number]}/{scenario_names[scenario_number]}/transformer/' \
                 f'ng{ngram_length}' \
                 f'_ta{thread_aware}' \
                 f'_epochs{epochs}' \
                 '.model'

    model_dir = os.path.split(model_path)[0]
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

    # embedding
    name = SyscallName()

    int_embedding = IntEmbedding()

    ngram = Ngram(
        feature_list=[int_embedding],
        thread_aware=thread_aware,
        ngram_length=ngram_length
    )

    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    # decision engine (DE)
    transformer = Transformer(
        input_vector=ngram,
        distinct_syscalls=distinct_syscalls,
        model_path=model_path,
        retrain=retrain,
        epochs=epochs,
        batch_size=batch_size,
        anomaly_scoring=anomaly_score
    )

    # define the used features and train
    ids = IDS(
        data_loader=dataloader,
        resulting_building_block=transformer,
        plot_switch=True
    )

    # threshold
    ids.determine_threshold()

    performance = ids.detect()
    stats = performance.get_results()

    ids.draw_plot()

    if stats is None:
        stats = {}
    stats['scenario'] = scenario_names[scenario_number]
    stats['anomaly_score'] = anomaly_score.name
    stats['ngram'] = ngram_length
    stats['batch_size'] = batch_size
    stats['epochs'] = epochs

    pprint(stats)
    result_path = 'persistent_data/transformer.json'
    save_to_json(stats, result_path)
    print_as_table(path=result_path)
