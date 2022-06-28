import os
from pprint import pprint

from algorithms.decision_engines.som import Som
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':

    # scenarios orderd by training data size asc
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

    # todo: set config
    ###################
    # feature config:
    ngram_length = 7
    w2v_size = 5
    som_epochs = 1000
    som_size = 50
    thread_aware = True

    # run config
    scenario_range = scenario_names[0:1]
    lid_ds_base_path = "/media/sf_Masterarbeit/Material/LID-DS-2021"
    ###################

    for scenario_number in range(0, len(scenario_range)):
        scenario_path = os.path.join(lid_ds_base_path, scenario_range[scenario_number])
        dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

        # features
        ###################

        
        
        
        w2v = W2VEmbedding(epochs=50,
                           scenario_path=scenario_path,
                           vector_size=w2v_size,
                           window_size=ngram_length)
        ngram = Ngram([w2v], thread_aware, ngram_length)
        
        ohe = OneHotEncoding(input=ngram)
        
        som = Som(ohe, epochs=som_epochs, size=som_size)
        config_name = f"som_n_{ngram_length}_w_{w2v_size}_e_{som_epochs}_t_{thread_aware}"

        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=som,
                  create_alarms=False,
                  plot_switch=False)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        ids.do_detection()
        # print results
        results = ids.performance.get_performance()
        pprint(results)

        # enrich results with configuration and save to disk
        results['algorithm'] = "SOM"
        results['ngram_length'] = ngram_length
        results['w2v_size'] = w2v_size
        results['thread_aware'] = thread_aware
        results['config'] = ids.get_config()
        results['scenario'] = scenario_range[scenario_number]
        result_path = 'results/results_som.json'

        som.show_distance_plot()

# Somehow I have to extract the Systemcalls and so on. Lets begin.