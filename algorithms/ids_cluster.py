'''
    example script for IDS on cluster
'''
import time
import math
import logging
import argparse
import traceback

from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.ids import IDS

# from algorithms.features.impl.mode import Mode
# from algorithms.features.impl.flags import Flags
from algorithms.features.impl.ngram import Ngram
# from algorithms.features.impl.concat import Concat
# from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.int_embedding import IntEmbedding

from algorithms.decision_engines.stide import Stide

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
        parser.add_argument('-t', dest='thread_aware', type=lambda x: (str(x).lower() == 'true'), required=True,
                            help='Set ngram to thread aware')

        args = parser.parse_args()
        print(f"Start with scenario {args.scenario}")

        scenario = args.scenario
        thread_aware = args.thread_aware
        window_length = args.window_length
        ngram_length = args.ngram_length
        embedding_size = args.embedding_size
        hidden_size = int(math.sqrt(ngram_length * embedding_size))
        direction = Direction.BOTH
        dataloader = dataloader_factory(args.base_path + scenario, direction=direction)
        ### building blocks
        # first: map each systemcall to an integer
        syscall_embedding = IntEmbedding()
        # flags = Flags()
        # mode = Mode()
        # process = ProcessName()
        # process_embedding = IntEmbedding(process)
        # concat = Concat([syscall_embedding, mode, flags])  # , process_embedding])
        # # now build ngrams from these integers
        ngram = Ngram([syscall_embedding], thread_aware, ngram_length)
        # finally calculate the STIDE algorithm using these ngrams
        de = Stide(ngram, window_length=window_length)

        ### the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=de,
                  create_alarms=True,
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
        results['dataset'] = 'LID-DS-2019'
        results['scenario'] = scenario
        results['ngram_length'] = ngram_length
        results['embedding'] = 'INT'
        results['algorithm'] = 'STIDE'
        results['direction'] = DIRECTION
        results['stream_sum'] = window_length
        results['detection_time'] = detection_time
        results['config'] = ids.get_config()
        results['thread_aware'] = thread_aware
        results['flag'] = False
        results['mode'] = False
        results['cluster'] = True
        results['parallel'] = False
        results['process_name'] = False
        save_to_mongo(results)
    except KeyError as e:
        print(traceback.format_exc())
        print('Experiment failed')
        logging.error('Failed for scenario: %s ngram: %d window: %d',
                      scenario,
                      ngram_length,
                      window_length)
