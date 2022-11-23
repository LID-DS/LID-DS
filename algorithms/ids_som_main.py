import os
import sys

from pprint import pprint

from datetime import datetime

from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from algorithms.ids import IDS
from algorithms.persistance import save_to_mongo

from dataloader.direction import Direction

from algorithms.decision_engines.som import Som

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding

from dataloader.dataloader_factory import dataloader_factory

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


    # feature config:
    NGRAM_LENGTH = 7
    W2V_SIZE = 5
    SOM_EPOCHS = 100
    SOM_SIZE = 50
    THREAD_AWARE = True

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
        dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

        # features
        ###################
        syscallName = SyscallName()
        intEmbedding = IntEmbedding(syscallName)
        
        w2v = W2VEmbedding(word=intEmbedding,
                           vector_size=W2V_SIZE,
                           window_size=NGRAM_LENGTH,
                           epochs=50
                           )
        ngram = Ngram([w2v], THREAD_AWARE, NGRAM_LENGTH)
        som = Som(ngram, epochs=SOM_EPOCHS, size=SOM_SIZE)
        decider = MaxScoreThreshold(som)

        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=decider,
                  create_alarms=False,
                  plot_switch=False)

        print("at evaluation:")
        # detection
        results = ids.detect_parallel().get_results()
        pprint(results)

        # enrich results with configuration and save to mongoDB
        results['config'] = ids.get_config_tree_links()
        results['scenario'] = scenario_name 
        results['ngram_length'] = NGRAM_LENGTH
        results['thread_aware'] = THREAD_AWARE
        results['w2v_size'] = W2V_SIZE
        results['dataset'] = LID_DS_VERSION[LID_DS_VERSION_NUMBER]
        results['direction'] = dataloader.get_direction_string()
        results['date'] = str(datetime.now().date())
        result_path = 'results/results_som.json'

        save_to_mongo(results)
