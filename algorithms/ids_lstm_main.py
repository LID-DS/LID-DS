"""
example script for running LSTM
"""
import os
import sys
import time

from pprint import pprint
from datetime import datetime

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
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from algorithms.persistance import save_to_mongo

from algorithms.ids import IDS
from algorithms.decision_engines.lstm import LSTM


if __name__ == '__main__':

    LID_DS_VERSION_NUMBER = 0
    LID_DS_VERSION = [
            "LID-DS-2019",
            "LID-DS-2021"
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
    SCENARIO_RANGE = SCENARIOS[0:1] 

    # config
    HIDDEN_DIM = 64
    HIDDEN_LAYERS = 1
    NGRAM_LENGTH = 3
    EMBEDDING_SIZE = 4
    THREAD_AWARE = True
    BATCH_SIZE = 1024
    USE_THREAD_CHANGE_FLAG = False
    USE_RETURN_VALUE = False
    USE_TIME_DELTA = False


    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        LID_DS_BASE_PATH = sys.argv[1]
    else:
        try:
            LID_DS_BASE_PATH = os.environ['LID_DS_BASE']
        except KeyError as exc:
            raise ValueError("No LID-DS Base Path given."
                             "Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE") from exc

    for scenario_name in SCENARIO_RANGE:
        scenario_path = os.path.join(LID_DS_BASE_PATH,
                                     LID_DS_VERSION[LID_DS_VERSION_NUMBER],
                                     scenario_name)

        # data loader for scenario
        dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)
        element_size = EMBEDDING_SIZE + USE_RETURN_VALUE + USE_TIME_DELTA
        # embedding
        int_embedding = IntEmbedding()
        w2v = W2VEmbedding(word=int_embedding,
                           vector_size=EMBEDDING_SIZE,
                           window_size=NGRAM_LENGTH,
                           epochs=5000)
        feature_list = [w2v]
        if USE_RETURN_VALUE:
            rv = ReturnValue()
            feature_list.append(rv)
        if USE_TIME_DELTA:
            td = TimeDelta(thread_aware=True)
            feature_list.append(td)
        ngram = Ngram(
            feature_list=feature_list,
            thread_aware=THREAD_AWARE,
            ngram_length=NGRAM_LENGTH + 1
        )
        ngram_minus_one = NgramMinusOne(
            ngram=ngram,
            element_size=element_size
        )
        final_features = [int_embedding, ngram_minus_one]
        if USE_THREAD_CHANGE_FLAG:
            tcf = ThreadChangeFlag(ngram_minus_one)
            final_features.append(tcf)
        concat = Concat(final_features)
        model_path = f'Models/{scenario_name}/LSTM/'\
            f'hid{HIDDEN_DIM}' \
            f'ta{THREAD_AWARE}' \
            f'ng{NGRAM_LENGTH}' \
            f'-emb{EMBEDDING_SIZE}' \
            f'-rv{USE_RETURN_VALUE}' \
            f'-td{USE_TIME_DELTA}' \
            f'-tcf{USE_THREAD_CHANGE_FLAG}.model'
        input_dim = (NGRAM_LENGTH * element_size +
                     USE_THREAD_CHANGE_FLAG)
        # decision engine (DE)
        distinct_syscalls = dataloader.distinct_syscalls_training_data()

        lstm = LSTM(input_vector=concat,
                    distinct_syscalls=distinct_syscalls,
                    input_dim=input_dim,
                    epochs=20,
                    hidden_layers=HIDDEN_LAYERS,
                    hidden_dim=HIDDEN_DIM,
                    batch_size=BATCH_SIZE,
                    force_train=False,
                    model_path=model_path)

        decider = MaxScoreThreshold(lstm)
        # define the used features
        print(type(lstm))
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=decider,
                  create_alarms=False,
                  plot_switch=False)
        start = time.time()
        # detection
        performance = ids.detect()
        results = performance.get_results()
        end = time.time()
        detection_time = (end - start)/60  # in min

        # results['config'] = ids.get_config_tree_links()
        results['dataset'] = LID_DS_VERSION[LID_DS_VERSION_NUMBER]
        pprint(results)
        # results['direction'] = dataloader.get_direction_string()
        results['date'] = str(datetime.now().date())
        results['scenario'] = scenario_name 
        results['ngram_length'] = NGRAM_LENGTH
        results['thread_aware'] = THREAD_AWARE
        results['detection_time'] = detection_time
        save_to_mongo(results)
