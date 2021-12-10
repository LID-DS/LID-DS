from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.ngram import Ngram

from algorithms.persistance import save_to_json, print_as_table

from algorithms.decision_engines.lstm import LSTM

from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from pprint import pprint
import time

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    SCENARIOS = [
        # 'Bruteforce_CWE-307'
        # 'CVE-2012-2122'
        # 'CVE-2014-0160'
        'CVE-2017-7529'
        # 'CVE-2018-3760'
        # 'CVE-2019-5418'
        # 'EPS_CWE-434.tar.gz'
        # 'PHP_CWE-434.tar.gz'
        # 'ZipSlip.tar.gz'
    ]
    NGRAM = [4, 6]
    EMBEDDING_SIZE = [6, 8]
    THREAD_AWARE = [True]
    RETURN_VALUE = [False, True]
    THREAD_CHANGE_FLAG = [False, True]
    TIME_DELTA = [False, True]
    BATCH_SIZE = [1024]
    for batch_size in BATCH_SIZE:
        for embedding_size in EMBEDDING_SIZE:
            for thread_aware in THREAD_AWARE:
                for use_time_delta in TIME_DELTA:
                    for use_thread_change_flag in THREAD_CHANGE_FLAG:
                        for use_return_value in RETURN_VALUE:
                            for ngram_length in NGRAM:
                                for scenario in SCENARIOS:
                                    scenario_path = f'../../Dataset/{scenario}/'

                                    # data loader for scenario
                                    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)

                                    element_size = embedding_size
                                    # embedding
                                    w2v = W2VEmbedding(
                                        vector_size=embedding_size,
                                        window_size=10,
                                        epochs=5000,
                                        scenario_path=scenario_path,
                                        path=f'Models/{scenario}/W2V/',
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
                                        td = TimeDelta(thread_aware=True)
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

                                    # decision engine (DE)
                                    distinct_syscalls = dataloader.distinct_syscalls_training_data()
                                    lstm = LSTM(element_size=element_size,
                                                use_thread_change_flag=use_thread_change_flag,
                                                ngram_length=ngram_length,
                                                distinct_syscalls=distinct_syscalls,
                                                epochs=20,
                                                batch_size=batch_size,
                                                force_train=False,
                                                model_path=f'Models/{scenario}/LSTM/')

                                    # define the used features
                                    ids = IDS(data_loader=dataloader,
                                              feature_list=feature_list,
                                              decision_engine=lstm,
                                              plot_switch=True)

                                    # training
                                    ids.train_decision_engine()
                                    # threshold
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
                                    stats['detection_time'] = detection_time
                                    result_path = 'persistent_data/lstm.json'
                                    save_to_json(stats, result_path)
                                    print_as_table(path=result_path)
