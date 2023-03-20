import argparse
import json
import os
import sys
from datetime import datetime

from algorithms.data_preprocessor import DataPreprocessor
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.util.dependency_graph_encoding import dependency_graph_to_config_tree
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from tools.ngram_entropy.ngram_entropy import NgramEntropy


def _parse_args():
    parser = argparse.ArgumentParser(description='Calculate the entropy for a given ngram length')

    parser.add_argument(
        '-d', dest='base_path', action='store', type=str, required=True,
        help='LID-DS base path'
    )
    parser.add_argument(
        '-v', dest='lid_ds_version', action='store', type=str, required=True,
        help='LID-DS version'
    )

    parser.add_argument(
        '-s', dest='scenario', action='store', type=str, required=True,
        help='Scenario name'
    )
    parser.add_argument(
        '-c', dest='checkpoint_dir', action='store', type=str, required=True,
        help='Checkpoint directory'
    )

    parser.add_argument(
        '-n', dest='ngram_length', action='store', type=int, required=True,
        help='Ngram length'
    )

    parser.add_argument(
        '-direction', dest='direction', action='store', type=Direction.argparse, required=True,
        help='Direction'
    )

    return parser.parse_args()


LID_DS_VERSION_NUMBER = 2
LID_DS_VERSIONS = [
    "LID-DS-2019",
    "LID-DS-2021",
    "LID-DS-2019_2"
]

# scenarios ordered by training data size asc
SCENARIOS = [
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


def main():
    SCENARIO_NAME = SCENARIOS[0]
    ###################
    # feature config:
    NGRAM_LENGTH = 5
    checkpoint_dir = "results"
    THREAD_AWARE = True
    DIRECTION = Direction.OPEN

    # run config
    ###################
    ON_CLUSTER = "IDS_ON_CLUSTER" in os.environ
    if ON_CLUSTER:
        print("Running on cluster")
        # get the LID-DS base path from argument or environment variable
        args = _parse_args()
        LID_DS_BASE_PATH = args.base_path
        LID_DS_VERSION = args.lid_ds_version
        SCENARIO_NAME = args.scenario
        NGRAM_LENGTH = args.ngram_length
        checkpoint_dir = args.checkpoint_dir
        DIRECTION = args.direction

    else:
        print("Running locally")
        # get the LID-DS base path from argument or environment variable
        if len(sys.argv) > 1:
            LID_DS_BASE_PATH = sys.argv[1]
        else:
            try:
                LID_DS_BASE_PATH = os.environ['LID_DS_BASE']
            except KeyError as exc:
                raise ValueError(
                    "No LID-DS Base Path given."
                    "Please specify as argument or set Environment Variable "
                    "$LID_DS_BASE"
                ) from exc
        LID_DS_VERSION = LID_DS_VERSIONS[LID_DS_VERSION_NUMBER]

    scenario_path = os.path.join(
        LID_DS_BASE_PATH,
        LID_DS_VERSION,
        SCENARIO_NAME
    )

    dataloader = dataloader_factory(scenario_path, direction=DIRECTION)

    # features
    ###################
    syscallName = SyscallName()
    intEmbedding = IntEmbedding(syscallName)
    ngram = Ngram(
        feature_list=[intEmbedding],
        thread_aware=THREAD_AWARE,
        ngram_length=NGRAM_LENGTH
    )
    entropy = NgramEntropy(ngram)

    data_preprocessor = DataPreprocessor(dataloader, entropy)

    results = entropy.get_result()

    # enrich results with configuration
    results['config'] = dependency_graph_to_config_tree(
        data_preprocessor.get_building_block_manager().get_dependency_graph()
    )
    results['scenario'] = SCENARIO_NAME
    results['dataset'] = LID_DS_VERSION
    results['direction'] = dataloader.get_direction_string()
    results['date'] = str(datetime.now().date())
    results['ngram_length'] = NGRAM_LENGTH

    # TODO: change to mongoDB
    result_path = f'{checkpoint_dir}/entropy/{LID_DS_VERSION}/{SCENARIO_NAME}/n{NGRAM_LENGTH}_d{DIRECTION.name}_t{THREAD_AWARE}_result.json'
    os.makedirs(os.path.dirname(result_path), exist_ok=True)

    with open(result_path, 'w') as file:
        json.dump(results, file, indent=2)


if __name__ == '__main__':
    main()
