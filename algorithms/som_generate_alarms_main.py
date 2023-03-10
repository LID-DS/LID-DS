import os
import sys
import json

from pprint import pprint

from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.syscall_name import SyscallName

from algorithms.ids import IDS

from dataloader.direction import Direction

from algorithms.persistance import save_to_json

from algorithms.decision_engines.som import Som

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding

from dataloader.dataloader_factory import dataloader_factory

from dataloader.data_loader_2021 import DataLoader2021


if __name__ == '__main__':

    lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019",
        "LID-DS-2021"
    ]

    # scenarios orderd by training data size asc
    # 0 - 14    
    scenario_names = [
        "CVE-2017-7529",
        "CVE-2014-0160",
        "CVE-2012-2122",
        "Bruteforce_CWE-307",
        "CWE-89-SQL-injection",
        "PHP_CWE-434",
        "ZipSlip",
        "CVE-2018-3760",
        "CVE-2020-9484",
        "CVE-2019-5418",
        "Juice-Shop",
        "CVE-2020-13942",
        "CVE-2017-12635_6"
    ]

    # todo: set config
    ###################
    # feature config:
    ngram_length = 7
    w2v_size = 5
    som_epochs = 100
    thread_aware = True

    # run config
    generate_and_write_alarms = True
    scenario_range = scenario_names[6:]
    ###################

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError:
            raise ValueError("No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE")

    for scenario in scenario_range:
        scenario_path = os.path.join("/media/felix/PortableSSD/datasets/LID-DS-2021",
                                     scenario)
        print(scenario_path)
        dataloader = DataLoader2021(scenario_path, direction=Direction.OPEN)

        # features
        ###################
        syscallName = SyscallName()
        intEmbedding = IntEmbedding(syscallName)
        w2v = W2VEmbedding(word=intEmbedding,           
                           vector_size=w2v_size,
                           window_size=ngram_length,
                           epochs=50
                           )
        ngram = Ngram([w2v], thread_aware, ngram_length)
        som = Som(ngram, epochs=som_epochs)
        decider = MaxScoreThreshold(som)

        config_name = f"alarms_SOM_n_{ngram_length}_w_{w2v_size}_e_{som_epochs}_t_{thread_aware}_{scenario}"

        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=decider,
                  create_alarms=generate_and_write_alarms,
                  plot_switch=False)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        # print results
        results = ids.detect_parallel().get_results()
        pprint(results)

        # enrich results with configuration and save to disk
        results['algorithm'] = "SOM"
        results['ngram_length'] = ngram_length
        results['w2v_size'] = w2v_size
        results['thread_aware'] = thread_aware
        results['config'] = ids.get_config()
        results['scenario'] = scenario
        result_path = 'results/results_som.json'
        save_to_json(results, result_path)

        # alarms - you need the directory "algorithms/results" existing for this to work.
        if generate_and_write_alarms:
            with open(
                    f"results/alarms_{config_name}_{scenario}.json",
                    'w') as jsonfile:
                json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
