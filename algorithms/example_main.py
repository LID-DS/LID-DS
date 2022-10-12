from pprint import pprint
import sys
import os

import datetime

from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.ngram import Ngram
from algorithms.ids import IDS
from algorithms.persistance import save_to_mongo

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError:
            raise ValueError("No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE")

    lid_ds_version = "LID-DS-2019"
    scenario_name = "CVE-2017-7529"
    #scenario_name = "CVE-2014-0160"
    #scenario_name = "Bruteforce_CWE-307"
    #scenario_name = "CVE-2012-2122"

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # just load < closing system calls for this example

    ### features (for more information see Paper: "Improving Host-based Intrusion Detection Using Thread Information", International Symposium on Emerging Information Security and Applications (EISA), 2021)
    thread_aware = False
    window_length = 100
    ngram_length = 7

    ### building blocks    
    # first: map each systemcall to an integer
    int_embedding = IntEmbedding()
    # now build ngrams from these integers
    ngram = Ngram([int_embedding], thread_aware, ngram_length)
    # finally calculate the STIDE algorithm using these ngrams
    stide = Stide(ngram, window_length)

    ### the IDS
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=True,
            plot_switch=False)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()

    # detection
    # normal / seriell
    # results = ids.detect().get_results()

    # parallel / map-reduce
    performance = ids.detect_parallel()
    results = performance.get_results()

    # to get alarms:
    # print(performance.alarms.alarm_list)

    ### print results
    pprint(results)

    # enrich results with configuration and save to mongoDB
    results['config'] = ids.get_config_tree_links()
    results['scenario'] = scenario_name
    results['dataset'] = lid_ds_version
    results['direction'] = dataloader.get_direction_string()
    results['date'] = str(datetime.datetime.now().date())

    save_to_mongo(results)
