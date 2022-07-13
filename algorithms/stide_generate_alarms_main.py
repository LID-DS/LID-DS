import os
import sys
import json
from pprint import pprint

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.persistance import save_to_json

if __name__ == '__main__':

    select_lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]

    # scenarios ordered by training data size asc
    # 0 - 14    
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
        except KeyError:
            raise ValueError("No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE")

    for select_scenario_number in range(0, len(scenario_names)):
        for thread_aware in [False, True]:
            for ngram_length in [3, 5, 7]:
                scenario_path = f"{lid_ds_base_path}/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}"        
                dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

                # features
                ###################
                window_length = 100
                ngram = Ngram([IntEmbedding()], thread_aware, ngram_length)   
                stide = Stide(ngram, window_length)    
                config_name = f"n_{ngram_length}_w_{window_length}_t_{thread_aware}"

                ###################
                # the IDS
                generate_and_write_alarms = True
                ids = IDS(data_loader=dataloader,
                        resulting_building_block=stide,
                        create_alarms=generate_and_write_alarms,
                        plot_switch=False)

                print("at evaluation:")
                # threshold
                ids.determine_threshold()
                # detection
                ids.detect()
                # print results
                results = ids.performance.get_performance()
                pprint(results)
                
                # enrich results with configuration and save to disk
                results['algorithm'] = "STIDE"
                results['ngram_length'] = ngram_length
                results['window_length'] = window_length
                results['thread_aware'] = thread_aware
                results['config'] = ids.get_config()
                results['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
                result_path = 'results/results_stide_LID-DS-2021.json'
                save_to_json(results, result_path)

                # alarms
                if generate_and_write_alarms:
                    with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
                        json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)

                # plot
                ids.draw_plot()
