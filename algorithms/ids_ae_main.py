import os
import sys
from datetime import datetime


from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.ids import IDS

from algorithms.decision_engines.ae import AE
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

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

    # feature config:
    NGRAM_LENGTH = 7
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

        dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

        # features
        ###################
        name = SyscallName()
        ohe = OneHotEncoding(name)
        ngram = Ngram(feature_list=[ohe],
                        thread_aware=THREAD_AWARE,
                        ngram_length=NGRAM_LENGTH
                        )
        # pytorch impl.
        ae = AE(
            input_vector=ngram
        )
        decider = MaxScoreThreshold(ae)
        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                    resulting_building_block=decider,
                    create_alarms=False,
                    plot_switch=False)

        print("at evaluation:")
        # detection
        # performance = ids.detect_parallel()
        performance = ids.detect()
        results = performance.get_results() 
        
        pprint(results)
        ids.draw_plot()
        

        # enrich results with configuration and save to disk
        results['config'] = ids.get_config_tree_links()
        results['dataset'] = LID_DS_VERSION[LID_DS_VERSION_NUMBER]
        results['direction'] = dataloader.get_direction_string()
        results['date'] = str(datetime.now().date())
        results['scenario'] = scenario_name
        results['ngram_length'] = NGRAM_LENGTH
        results['thread_aware'] = THREAD_AWARE

        save_to_mongo(results)
