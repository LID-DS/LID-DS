from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.ngram import Ngram

from algorithms.decision_engines.lstm import LSTM

from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from pprint import pprint

import argparse
import time
import csv

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
                        help='Scenario name')
    parser.add_argument('-e', dest='embedding_size', action='store', type=int, required=True,
                        help='Scenario name')
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

    ngram_length = args.ngram_length
    embedding_size = args.embedding_size
    scenario = args.scenario
    scenario_path = args.base_path + args.scenario
    batch_size = args.batch_size
    epochs = args.epochs
    thread_aware = False
    if args.thread_aware:
        thread_aware = True
    use_return_value = False
    if args.return_value:
        use_return_value = True
    use_thread_change_flag = False
    if args.thread_change_flag:
        use_thread_change_flag = True
    use_time_delta = False
    if args.time_delta:
        use_time_delta = True

    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)

    element_size = embedding_size

    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=5000,
        scenario_path=scenario_path,
        path=f'Models/{scenario}/W2V',
        force_train=True,
        distinct=True,
        thread_aware=True
    )
    feature_list = [w2v]
    if use_return_value:
        element_size += 1
        rv = ReturnValue()
        feature_list.append(rv)
    if use_time_delta:
        td = TimeDelta()
        element_size += 1
        feature_list.append(td)
    ngram = Ngram(
        feature_list=feature_list,
        thread_aware=thread_aware,
        ngram_length=ngram_length + 1
    )
    ngram_minus_one = NgramMinusOne(
        ngram=ngram,
        element_size=element_size
    )
    int_embedding = IntEmbedding()
    feature_list = [int_embedding,
                    ngram_minus_one]
    if use_thread_change_flag:
        tcf = ThreadChangeFlag(ngram_minus_one)
        feature_list.append(tcf)

    distinct_syscalls = dataloader.distinct_syscalls_training_data()
    de = LSTM(
        element_size=element_size,
        use_thread_change_flag=use_thread_change_flag,
        ngram_length=ngram_length,
        distinct_syscalls=distinct_syscalls,
        epochs=epochs,
        batch_size=batch_size,
        force_train=True,
        model_path=f'Models/{scenario}/LSTM'
    )
    # define the used features
    ids = IDS(data_loader=dataloader,
              feature_list=feature_list,
              decision_engine=de,
              plot_switch=False)

    ids.train_decision_engine()
    ids.determine_threshold()
    start = time.time()
    ids.do_detection()
    end = time.time()
    detection_time = end - start
    performance = ids.performance.get_performance()
    pprint(performance)
    stats = {}
    stats['scenario'] = scenario
    stats['ngram'] = ngram_length
    stats['batch_size'] = batch_size
    stats['embedding_size'] = embedding_size
    stats['return_value'] = use_return_value
    stats['thread_change_flag'] = use_thread_change_flag
    stats['time_delta'] = use_time_delta
    stats['alarm_count'] = performance['alarm_count']
    stats['cfp_exp'] = performance['consecutive_false_positives_exploits']
    stats['cfp_norm'] = performance['consecutive_false_positives_normal']
    stats['detection_rate'] = performance['detection_rate']
    stats['fp'] = performance['false_positives']
    stats['detection_time'] = detection_time

    csv_file = "stats.csv"
    csv_columns = ['scenario',
                   'ngram',
                   'batch_size',
                   'embedding_size',
                   'return_value',
                   'thread_change_flag',
                   'time_delta',
                   'alarm_count',
                   'cfp_exp',
                   'cfp_norm',
                   'detection_rate',
                   'fp',
                   'detection_time']
    try:
        with open(csv_file, 'a') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
            # writer.writeheader()
            writer.writerow(stats)
    except IOError:
        print("I/O error")
