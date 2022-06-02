from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.ngram import Ngram

from algorithms.persistance import save_to_json, print_as_table

from algorithms.decision_engines.lstm import LSTM

from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from pprint import pprint

import traceback
import argparse
import time

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
    print(f'Start with scenario {args.scenario}')

    try:
        hidden_dim = 64
        hidden_layers = 1
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
            epochs=500,
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
            td = TimeDelta(thread_aware=thread_aware)
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
        input_dim = (ngram_length * (embedding_size +
                                     use_return_value +
                                     use_time_delta) +
                    use_thread_change_flag)
        model_path = f'Models/{scenario}/LSTM/'\
            f'hid{hidden_dim}' \
            f'ta{thread_aware}' \
            f'ng{ngram_length}' \
            f'-emb{embedding_size}' \
            f'-rv{use_return_value}' \
            f'-td{use_time_delta}' \
            f'-tcf{use_thread_change_flag}.model'
        print('DEFINE LSTM')
        de = LSTM(
            distinct_syscalls=distinct_syscalls,
            input_dim=input_dim,
            epochs=epochs,
            hidden_layers=hidden_layers,
            hidden_dim=hidden_dim,
            batch_size=batch_size,
            force_train=True,
            model_path=model_path
        )
        # define the used features
        ids = IDS(data_loader=dataloader,
                  feature_list=feature_list,
                  decision_engine=de,
                  plot_switch=False)

        train_start = time.time()
        ids.train_decision_engine()
        train_end = time.time()
        train_time = train_end - train_start
        ids.determine_threshold()
        start = time.time()
        ids.do_detection()
        end = time.time()
        detection_time = end - start
        stats = ids.performance.get_performance()
        pprint(stats)
        stats['scenario'] = scenario
        stats['ngram'] = ngram_length
        stats['batch_size'] = batch_size
        stats['embedding_size'] = embedding_size
        stats['return_value'] = use_return_value
        stats['thread_change_flag'] = use_thread_change_flag
        stats['time_delta'] = use_time_delta
        stats['detection_time'] = detection_time/60
        stats['train_time'] = train_time/60
        result_path = 'persistent_data/panic.json'
        save_to_json(stats, result_path)
        print_as_table(path=result_path)
    except Exception as e:
        print(f'failed for scenario {scenario}')
        print(e)
        traceback.print_exc()
        stats = {}
        result_path = 'persistent_data/error_log.json'
        stats['scenario'] = scenario
        stats['ngram'] = ngram_length
        stats['batch_size'] = batch_size
        stats['embedding_size'] = embedding_size
        stats['return_value'] = use_return_value
        stats['thread_change_flag'] = use_thread_change_flag
        stats['time_delta'] = use_time_delta
        # stats['error_msg'] = e
        save_to_json(stats, result_path)
