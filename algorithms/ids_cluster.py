import time
import math
import argparse

from pprint import pprint

from algorithms.ids import IDS

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.features.impl.mode import Mode
from algorithms.features.impl.flags import Flags
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.int_embedding import IntEmbedding

from algorithms.decision_engines.stide import Stide

from algorithms.persistance import save_to_json




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
    parser.add_argument('-w', dest='window_length', action='store', type=int, required=True,
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
    print(f"Start with scenario {args.scenario}")

    scenario = args.scenario
    thread_aware = args.thread_aware
    window_length = args.window_length
    ngram_length = args.ngram_length
    embedding_size = args.embedding_size
    hidden_size = int(math.sqrt(ngram_length * embedding_size))

    dataloader = dataloader_factory(args.base_path + scenario, direction=Direction.OPEN)
    ### building blocks    
    # first: map each systemcall to an integer
    syscall_embedding = IntEmbedding()
    flags = Flags()
    mode = Mode()
    process = ProcessName()
    process_embedding = IntEmbedding(process)
    concat = Concat([syscall_embedding, mode, flags, process_embedding])
    # # now build ngrams from these integers
    ngram = Ngram([concat], thread_aware, ngram_length)
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
    results['scenario'] = scenario 
    results['ngram'] = ngram_length
    # results['embedding'] = embedding_size
    results['algorithm'] = 'stide'
    results['window'] = window_length 
    results['detection_time'] = detection_time
    results['flag'] = True
    results['mode'] = True
    results['process_name'] = True
    result_path = 'persistent_data/process_name.json'
    save_to_json(results, result_path)
