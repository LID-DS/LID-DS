import os
import sys
import torch

from datetime import datetime

from pprint import pprint

from algorithms.ids import IDS

from dataloader.direction import Direction

from algorithms.decision_engines.mlp import MLP

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.select import Select
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from dataloader.dataloader_factory import dataloader_factory

from algorithms.persistance import save_to_mongo

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
    ###################
    # feature config:
    NGRAM_LENGTH = 7
    W2V_SIZE = 5
    THREAD_AWARE = True
    HIDDEN_SIZE = 150
    HIDDEN_LAYERS = 4
    BATCH_SIZE = 50

    # run config
    ###################

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
        dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

        # features
        ###################
        syscallName = SyscallName()
        intEmbedding = IntEmbedding(syscallName)
        
        w2v = W2VEmbedding(word=intEmbedding,
                           vector_size=W2V_SIZE,
                           window_size=NGRAM_LENGTH,
                           epochs=50          
                           )
        ngram = Ngram(feature_list=[w2v],
                      thread_aware=THREAD_AWARE,
                      ngram_length=NGRAM_LENGTH + 1
                      )
        
        select = Select(ngram, start = 0, end = NGRAM_LENGTH * W2V_SIZE)

        ohe = OneHotEncoding(intEmbedding)

        mlp = MLP(
            input_vector=select,
            output_label=ohe,
            hidden_size=HIDDEN_SIZE,
            hidden_layers=HIDDEN_LAYERS,
            batch_size=BATCH_SIZE,
            learning_rate=0.003
        )

        decider = MaxScoreThreshold(mlp)
        # Seeding
        torch.manual_seed(0)

        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=decider,
                  create_alarms=False,
                  plot_switch=False)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection        
        # print results
        results = ids.detect().get_results()
        pprint(results)

        # enrich results with configuration and save to disk
        results['config'] = ids.get_config_tree_links()
        results['dataset'] = LID_DS_VERSION[LID_DS_VERSION_NUMBER]
        results['direction'] = dataloader.get_direction_string()
        results['date'] = str(datetime.now().date())
        results['scenario'] = scenario_name
        results['ngram_length'] = NGRAM_LENGTH
        results['w2v_size'] = W2V_SIZE
        results['thread_aware'] = THREAD_AWARE
        results['scenario'] = scenario_name 

        print(mlp.get_net_weights())
        save_to_mongo(results)
