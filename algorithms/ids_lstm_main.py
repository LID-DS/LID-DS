"""
example script for running LSTM
"""
import os
import sys
import time
from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag

from algorithms.persistance import save_to_json, print_as_table

from algorithms.ids import IDS
from algorithms.decision_engines.lstm import LSTM


if __name__ == '__main__':
    LID_DS_VERSION_NUMBER = 0
    lid_ds_version = [
        "LID-DS-2019",
        "LID-DS-2021"
    ]

    scenario_number = 0
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

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError as exc:
            raise ValueError("No LID-DS Base Path given. Please specify "
                             "as argument or set Environment Variable "
                             "$LID_DS_BASE") from exc

    # config
    hidden_dim = 64
    hidden_layers = 1
    ngram_length = 3
    embedding_size = 4
    thread_aware = True
    batch_size = 1024
    use_thread_change_flag = False
    use_return_value = False
    use_time_delta = False
    scenario_path = f"{lid_ds_base_path}/{lid_ds_version[LID_DS_VERSION_NUMBER]}/{scenario_names[scenario_number]}"
    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)
    element_size = embedding_size + use_return_value + use_time_delta
    # embedding
    int_embedding = IntEmbedding()
    w2v = W2VEmbedding(word=int_embedding,
                       vector_size=embedding_size,
                       window_size=ngram_length,
                       epochs=5000)
    feature_list = [w2v]
    if use_return_value:
        rv = ReturnValue()
        feature_list.append(rv)
    if use_time_delta:
        td = TimeDelta(thread_aware=True)
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
    final_features = [int_embedding, ngram_minus_one]
    if use_thread_change_flag:
        tcf = ThreadChangeFlag(ngram_minus_one)
        final_features.append(tcf)
    concat = Concat(final_features)
    model_path = f'Models/{scenario_names[scenario_number]}/LSTM/'\
        f'hid{hidden_dim}' \
        f'ta{thread_aware}' \
        f'ng{ngram_length}' \
        f'-emb{embedding_size}' \
        f'-rv{use_return_value}' \
        f'-td{use_time_delta}' \
        f'-tcf{use_thread_change_flag}.model'
    input_dim = (ngram_length * element_size +
                 use_thread_change_flag)
    # decision engine (DE)
    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    lstm = LSTM(input_vector=concat,
                distinct_syscalls=distinct_syscalls,
                input_dim=input_dim,
                epochs=20,
                hidden_layers=hidden_layers,
                hidden_dim=hidden_dim,
                batch_size=batch_size,
                force_train=True,
                model_path=model_path)
    # define the used features
    print(type(lstm))
    ids = IDS(data_loader=dataloader,
              resulting_building_block=lstm,
              create_alarms=False,
              plot_switch=False)
    # threshold
    ids.determine_threshold()
    start = time.time()
    # detection
    stats = ids.detect().get_results()
    end = time.time()
    detection_time = (end - start)/60  # in min

    if stats is None:
        stats = {}
    stats['scenario'] = scenario_names[scenario_number]
    stats['ngram'] = ngram_length
    stats['batch_size'] = batch_size
    stats['embedding_size'] = embedding_size
    stats['return_value'] = use_return_value
    stats['thread_change_flag'] = use_thread_change_flag
    stats['time_delta'] = use_time_delta
    stats['detection_time'] = detection_time
    result_path = 'persistent_data/lstm.json'
    pprint(stats)
    #save_to_json(stats, result_path)
    #print_as_table(path=result_path)
