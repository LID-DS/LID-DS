import argparse
import os
import sys
import time
from datetime import datetime
from pprint import pprint

from algorithms.decision_engines.transformer import Transformer, AnomalyScore
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.ids import IDS
from algorithms.persistance import save_to_json, ModelCheckPoint
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

lid_ds_versions = [
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


def _parse_args():
    parser = argparse.ArgumentParser(description='Evaluate the Transformer based IDS ')

    parser.add_argument(
        '-d', dest='base_path', action='store', type=str, required=True,
        help='LID-DS base path'
    )
    parser.add_argument(
        '-v', dest='lid_ds_version', action='store', type=str, required=True,
        help='LID-DS version'
    )
    parser.add_argument(
        '-s', dest='scenario', action='store', type=str, required=False,
        help='Scenario name'
    )
    parser.add_argument(
        '-c', dest='checkpoint_dir', action='store', type=str, required=True,
        help='Models checkpoint base directory'
    )

    parser.add_argument(
        '-n', dest='ngram_length', action='store', type=int, required=True,
        help='Ngram length'
    )
    parser.add_argument(
        '-t', dest='thread_aware', type=lambda x: (str(x).lower() == 'true'), required=True,
        help='Thread aware ngrams'
    )

    parser.add_argument(
        '-f', dest='feedforward_dim', action='store', type=int, required=True,
        help='Feedforward dimension'
    )
    parser.add_argument(
        '-l', dest='layers', action='store', type=int, required=True,
        help='Number of encoder and decoder layers'
    )

    parser.add_argument(
        '-nh', dest='num_heads', action='store', type=int, required=True,
        help='Number of model heads'
    )

    parser.add_argument(
        '-m', dest='model_dim', action='store', type=int, required=True,
        help='TF model dimension (aka. emb size)'
    )

    parser.add_argument(
        '-lm', dest='language_model', type=lambda x: (str(x).lower() == 'true'), required=True,
        help='Use Language model architecture'
    )

    parser.add_argument(
        '-b', dest='batch_size', action='store', type=int, required=True,
        help='Training batch size'
    )

    parser.add_argument(
        '-dup', dest='dedup_train_set', type=lambda x: (str(x).lower() == 'true'), required=True,
        help='Deduplicate training set'
    )

    parser.add_argument(
        '-as', dest='anomaly_score', action='store', type=AnomalyScore.argparse,
        required=True,
        help='Anomaly scoring strategy'
    )

    return parser.parse_args()


def main():
    lid_ds_version_number = 1
    scenario_number = 0
    checkpoint_dir = "Models"
    retrain = False
    ngram_length = 11
    thread_aware = True
    language_model = True
    dedup_train_set = True

    anomaly_score = AnomalyScore.LAST
    layers = 6
    model_dim = 8
    pre_layer_norm = True

    feedforward_dim = 1024
    batch_size = 256
    num_heads = 2
    epochs = 20
    dropout = 0.1

    if "IDS_ON_CLUSTER" in os.environ:
        args = _parse_args()
        scenario = args.scenario
        lid_ds_version = args.lid_ds_version
        scenario_path = args.base_path + scenario
        checkpoint_dir = args.checkpoint_dir

        ngram_length = args.ngram_length
        thread_aware = args.thread_aware
        layers = args.layers
        model_dim = args.model_dim
        feedforward_dim = args.feedforward_dim
        num_heads = args.num_heads
        language_model = args.language_model
        dedup_train_set = args.dedup_train_set
        batch_size = args.batch_size
        anomaly_score = args.anomaly_score
    else:
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
        scenario = scenario_names[scenario_number]
        lid_ds_version = lid_ds_versions[lid_ds_version_number]
        scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario}"

    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

    checkpoint = ModelCheckPoint(
        scenario,
        lid_ds_version,
        "transformer",
        algo_config={
            "ngram_length": ngram_length,
            "thread_aware": thread_aware,
            "batch_size": batch_size,
            "layers": layers,
            "model_dim": model_dim,
            "num_heads": num_heads,
            "feedforward_dim": feedforward_dim,
            "pre_layer_norm": pre_layer_norm,
            "direction": dataloader.get_direction_string(),
            "language_model": language_model
            "dedup_train_set": dedup_train_set
        },
        models_dir=checkpoint_dir
    )

    # embedding
    name = SyscallName()

    int_embedding = IntEmbedding(name)

    ngram = Ngram(
        feature_list=[int_embedding],
        thread_aware=thread_aware,
        ngram_length=ngram_length
    )

    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    for epochs in reversed(range(5, 21, 5)):
        start = time.time()
        # decision engine (DE)
        transformer = Transformer(
            input_vector=ngram,
            distinct_syscalls=distinct_syscalls,
            retrain=retrain,
            epochs=epochs,
            batch_size=batch_size,
            anomaly_scoring=anomaly_score,
            checkpoint=checkpoint,
            layers=layers,
            model_dim=model_dim,
            num_heads=num_heads,
            dropout=dropout,
            feedforward_dim=feedforward_dim,
            pre_layer_norm=pre_layer_norm,
            language_model=language_model,
            dedup_train_set=dedup_train_set
        )

        decider = MaxScoreThreshold(transformer)

        ids = IDS(
            data_loader=dataloader,
            resulting_building_block=decider,
            plot_switch=False
        )

        performance = ids.detect()
        end = time.time()

        stats = performance.get_results()

        stats['dataset'] = lid_ds_version
        stats['scenario'] = scenario
        stats['anomaly_score'] = anomaly_score.name
        stats['ngram'] = ngram_length
        stats['batch_size'] = batch_size
        stats['epochs'] = epochs
        stats['model_dim'] = model_dim
        stats['num_heads'] = num_heads
        stats['layers'] = layers
        stats['dropout'] = dropout
        stats['feedforward_dim'] = feedforward_dim
        stats['thread_aware'] = thread_aware
        stats['threshold'] = decider._threshold
        stats['train_losses'] = transformer.train_losses
        stats['val_losses'] = transformer.val_losses
        stats['config'] = ids.get_config_tree_links()
        stats['direction'] = dataloader.get_direction_string()
        stats['date'] = str(datetime.now().date())
        stats['detection_time'] = str(end - start)

        pprint(stats)
        result_path = f'{checkpoint.model_path_base}/{checkpoint.model_name}.json'
        save_to_json(stats, result_path)


if __name__ == '__main__':
    main()
