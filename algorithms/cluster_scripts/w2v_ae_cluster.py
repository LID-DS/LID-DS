"""
    this is an example script to show how to use the LSTM DE with the following settings:
    convert syscall name to vector with length of embedding_size
    create thread aware ngrams of size ngram_length
    ignore current syscall in ngram (NgramMinusOne)
    add current syscall as int with (CurrentSyscallAsInt)
"""
import time
import math
import logging
import argparse
import traceback

from pprint import pprint
from datetime import datetime

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.ids import IDS

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from algorithms.decision_engines.ae import AE

from algorithms.persistance import save_to_mongo


if __name__ == '__main__':
    try:
        logging.basicConfig(filename='experiments.log', level=logging.WARNING)
        parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

        parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                            help='LID-DS Base Path')
        parser.add_argument('-s', dest='scenario', action='store', type=str, required=True,
                            help='Scenario name')
        parser.add_argument('-n', dest='ngram_length', action='store', type=int, required=True,
                            help='ngram length')
        parser.add_argument('-w', dest='window_length', action='store', type=int, required=True,
                            help='window length')
        parser.add_argument('-e', dest='embedding_size', action='store', type=int, required=True,
                            help='embedding size')
        parser.add_argument('-t', dest='thread_aware', action='store', type=bool, required=True,
                            help='Set ngram to thread aware')

        args = parser.parse_args()
        print(f"Start with scenario {args.scenario}")

        scenario = args.scenario
        thread_aware = args.thread_aware
        ngram_length = args.ngram_length
        embedding_size = args.embedding_size
        hidden_size = int(math.sqrt(ngram_length * embedding_size))
        direction = Direction.BOTH

        dataloader = dataloader_factory(args.base_path + scenario, direction=direction)
        ### building blocks
        # first: map each systemcall to an integer
        syscall_name = SyscallName()
        syscall_embedding = W2VEmbedding(syscall_name, embedding_size, ngram_length, 500)
        # # now build ngrams from these integers
        ngram = Ngram([syscall_embedding], thread_aware, ngram_length)
        # finally calculate the STIDE algorithm using these ngrams
        de = AE(ngram)
        max_score_threshold = MaxScoreThreshold(de)
        ### the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=max_score_threshold,
                  create_alarms=False,
                  plot_switch=False)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        start = time.time()
        performance = ids.detect_parallel()
        end = time.time()

        detection_time = (end - start)/60  # in min

        print(detection_time)
        ### print results and plot the anomaly scores
        results = performance.get_results()
        pprint(results)
        if direction == Direction.BOTH:
            DIRECTION = 'BOTH'
        elif direction == Direction.OPEN:
            DIRECTION = 'OPEN'
        else:
            DIRECTION = 'CLOSE'
        results['config'] = ids.get_config_tree_links()
        results['dataset'] = 'LID-DS-2019'
        results['scenario'] = scenario
        results['direction'] = dataloader.get_direction_string()
        results['date'] = str(datetime.datetime.now().date())

        save_to_mongo(results)
    except KeyError as e:
        print(traceback.format_exc())
        print('Experiment failed')
        logging.error('Failed for algorithm: %s scenario: %s ngram: %d',
                      'AE',
                      scenario,
                      ngram_length)
