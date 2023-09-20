import argparse
import os
import sys
import time
from datetime import datetime
from pprint import pprint

from algorithms.decision_engines.transformer import Transformer, AnomalyScore
from algorithms.features.impl.int_embedding import IntEmbeddingConcat
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.path_like_param import PathLikeParam
from algorithms.features.impl.path_preprocessor import PathPreprocessor
from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.quantile_bucketing import QuantileBucketing
from algorithms.features.impl.return_value import ReturnValueWithError
from algorithms.features.impl.subwordunits_tokenizer import SubWordUnitsTokenizer
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.ids import IDS
from algorithms.persistance import save_to_json, ModelCheckPoint, load_from_json
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
        '-e', dest='epochs', action='store', type=int,
        help='Epoch (useful when only evaluating)'
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
        '-b', dest='batch_size', action='store', type=int, required=True,
        help='Training batch size'
    )

    parser.add_argument(
        '-dup', dest='dedup_train_set', type=lambda x: (str(x).lower() == 'true'), required=True,
        help='Deduplicate training set'
    )

    parser.add_argument(
        '-as', dest='anomaly_score', action='store', type=AnomalyScore.argparse, required=True,
        help='Anomaly scoring strategy'
    )

    parser.add_argument(
        '-ret', dest='use_return_value', type=lambda x: (str(x).lower() == 'true'), default=False,
        help='Use return value'
    )

    parser.add_argument(
        '-pname', dest='use_process_name', type=lambda x: (str(x).lower() == 'true'), default=False,
        help='Use process name'
    )

    parser.add_argument(
        '-time', dest='use_time_delta', type=lambda x: (str(x).lower() == 'true'), default=False,
        help='Use time delta'
    )

    parser.add_argument(
        '-paths', dest='use_paths', type=lambda x: (str(x).lower() == 'true'), default=False,
        help='Use paths'
    )

    parser.add_argument(
        '-eval', dest='evaluate', type=lambda x: (str(x).lower() == 'true'),
        help='Evaluate model, if false only training is performed'
    )

    parser.add_argument(
        '-run', dest='run', type=int, required=False, default=0,
        help='Run number'
    )

    return parser.parse_args()


def main():
    lid_ds_version_number = 1
    scenario_number = 0
    checkpoint_dir = "Models"
    retrain = False
    evaluate = True
    ngram_length = 8
    thread_aware = True
    run = 0

    language_model = True
    dedup_train_set = True

    anomaly_score = AnomalyScore.LAST
    layers = 6
    model_dim = 8
    pre_layer_norm = True
    feedforward_dim = model_dim * 4
    batch_size = 256
    num_heads = 2
    epochs = 500
    dropout = 0.1
    learning_rate = 0.001

    use_return_value = False
    quantile_bucket_size = 5
    use_process_name = False
    use_time_delta = False
    use_paths = False

    ON_CLUSTER = "IDS_ON_CLUSTER" in os.environ
    if ON_CLUSTER:
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
        dedup_train_set = args.dedup_train_set
        batch_size = args.batch_size
        anomaly_score = args.anomaly_score
        use_return_value = args.use_return_value
        evaluate = args.evaluate
        epochs = args.epochs
        use_process_name = args.use_process_name
        use_time_delta = args.use_time_delta
        use_paths = args.use_paths
        run = args.run
        print(args)
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
    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

    checkpoint = ModelCheckPoint(
        scenario,
        lid_ds_version,
        "transformer",
        algo_config={
            "ngram": ngram_length,
            "tha": thread_aware,
            "batch": batch_size,
            "layers": layers,
            "m_dim": model_dim,
            "heads": num_heads,
            "ffd": feedforward_dim,
            "pre_ln": pre_layer_norm,
            "direction": dataloader.get_direction_string(),
            "lm": language_model,
            "dedup": dedup_train_set,
            "retval": use_return_value,
            "pname": use_process_name,
            "tdelta": use_time_delta,
            "paths": use_paths,
            "drop": dropout,
            "lr": learning_rate,
            "run": run,
        },
        models_dir=checkpoint_dir
    )

    # FEATURES
    name = SyscallName()

    features = [name]

    if use_return_value:
        return_value = QuantileBucketing(
            ReturnValueWithError(),
            num_buckets=quantile_bucket_size,
            excluded_values=[0]
        )
        features.append(return_value)
    if use_process_name:
        process_name = ProcessName()
        features.append(process_name)
    if use_time_delta:
        time_delta = QuantileBucketing(
            TimeDelta(thread_aware=thread_aware, min_max_scaling=False),
            num_buckets=quantile_bucket_size
        )
        features.append(time_delta)
    if use_paths:
        path_like_params = ['name', 'path', 'fd', 'in_fd']
        subword_model_path = f"{checkpoint.model_path_base}/subword_model/{'_'.join(path_like_params)}/"
        subword_path_like = SubWordUnitsTokenizer(
            feature=PathPreprocessor(PathLikeParam(path_like_params)),
            model_path_prefix=subword_model_path,
            max_pieces_length=5,
            vocab_size=150,
            min_piece_length=1,
        )
        features.append(subword_path_like)
    int_embedding = IntEmbeddingConcat(building_blocks=features)

    ngram = Ngram(
        feature_list=[int_embedding],
        thread_aware=thread_aware,
        ngram_length=ngram_length
    )
    if len(features) > 1:
        ngram = NgramMinusOne(ngram=ngram)

    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    def _run_for_epoch(epoch):
        if ON_CLUSTER:
            result_path = f'{checkpoint.model_path_base}/{checkpoint.model_name}_epoch{epoch}.json'
            last_results = load_from_json(result_path)
            if last_results:
                print(f"ALREADY EVALUATED: SKIPPING! \n{result_path=}")
                return
        else:
            result_path = f'{checkpoint.model_path_base}/{checkpoint.model_name}.json'

        if len(os.path.basename(result_path)) > 255:
            raise ValueError(f"Filename too long: {result_path}")

        start = time.time()
        # decision engine (DE)
        transformer = Transformer(
            input_vector=ngram,
            concat_int_embedding=int_embedding,
            retrain=retrain,
            epochs=epoch,
            batch_size=batch_size,
            anomaly_scoring=anomaly_score,
            checkpoint=checkpoint,
            layers=layers,
            model_dim=model_dim,
            num_heads=num_heads,
            dropout=dropout,
            feedforward_dim=feedforward_dim,
            pre_layer_norm=pre_layer_norm,
            dedup_train_set=dedup_train_set,
            learning_rate=learning_rate,
        )

        decider = MaxScoreThreshold(transformer)

        ids = IDS(
            data_loader=dataloader,
            resulting_building_block=decider,
            plot_switch=False
        )

        if evaluate:
            performance = ids.detect()
            end = time.time()

            stats = performance.get_results()
            stats['dataset'] = lid_ds_version
            stats['scenario'] = scenario
            stats['distinct_tokens'] = len(int_embedding)
            stats['direction'] = dataloader.get_direction_string()
            stats['detection_time'] = str(end - start)
            stats['threshold'] = decider._threshold
            stats['run'] = run

            pprint(stats)
            print(f"detection time: {stats['detection_time']}")

            stats['date'] = str(datetime.now().date())
            stats['train_losses'] = transformer.train_losses
            stats['val_losses'] = transformer.val_losses
            stats['train_set_size'] = transformer.train_set_size
            stats['val_set_size'] = transformer.val_set_size
            stats['config'] = ids.get_config_tree_links()

            save_to_json(stats, result_path)

    if (not ON_CLUSTER) and evaluate:
        for epochs in reversed(range(50, 601, 100)):
            _run_for_epoch(epochs)
    else:
        _run_for_epoch(epochs)


if __name__ == '__main__':
    main()