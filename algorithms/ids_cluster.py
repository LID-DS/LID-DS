import time
import argparse
import traceback

from pprint import pprint

from algorithms.ids import IDS

from algorithms.decision_engines.stide import Stide

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.int_embedding import IntEmbedding

from algorithms.persistance import save_to_json

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory



if __name__ == '__main__':
    """
    this is an example script to show how to use the LSTM DE with the following settings:
        convert syscall name to vector with length of embedding_size
        create thread aware ngrams of size ngram_length
        ignore current syscall in ngram (NgramMinusOne)
        add current syscall as int with (CurrentSyscallAsInt)
    """

    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

    parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('-s', dest='scenario', action='store', type=str, required=True,
                        help='Scenario name')
    parser.add_argument('-n', dest='ngram_length', action='store', type=int, required=True,
                        help='ngram length')
    parser.add_argument('-w', dest='window-length', action='store', type=int, required=True,
                        help='window length')
    parser.add_argument('-e', dest='embedding_size', action='store', type=int, required=True,
                        help='embedding size')
    parser.add_argument('-b', dest='batch_size', action='store', type=int, required=True,
                        help='Set batch size of IDS input')
    parser.add_argument('-ep', dest='epochs', action='store', type=int, required=True,
                        help='Set epochs of lstm to train')
    parser.add_argument('-ta', dest='thread_aware', action='store_true',
                        help='Set ngram to thread aware')
    parser.add_argument('-rv', dest='return_value', action='store_true',
                        help='Set IDS to use return value of syscall')
    parser.add_argument('-td', dest='time_delta', action='store_true',
                        help='Set IDS to use time_delta between syscalls')
    parser.add_argument('-tcf', dest='thread_change_flag', action='store_true',
                        help='Set IDS to use thread change flag of ngrams')

    args = parser.parse_args()
    print(f'Start with scenario {args.scenario}')

    thread_aware = True
    window_length = 100
    ngram_length = 5

    dataloader = dataloader_factory(base_path, direction=Direction.OPEN)
    ### building blocks    
    # first: map each systemcall to an integer
    int_embedding = IntEmbedding()
    # now build ngrams from these integers
    ngram = Ngram([int_embedding], thread_aware, ngram_length)
    # finally calculate the STIDE algorithm using these ngrams
    stide = Stide(ngram, window_length=window_length)

    ### the IDS    
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=True,
            plot_switch=False)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    start = time.time()
    ids.do_detection()
    end = time.time()

    detection_time = (end - start)/60  # in min


    ### print results and plot the anomaly scores
    results = ids.performance.get_performance()
    pprint(results)
    stats['scenario'] = 'Real world' 
    stats['ngram'] = ngram_length
    stats['detection_time'] = detection_time
    result_path = 'persistent_data/lstm.json'
    save_to_json(stats, result_path)
