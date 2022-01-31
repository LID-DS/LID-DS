import json
from pprint import pprint
from datetime import datetime

from pandas import concat

from algorithms.decision_engines.ae import AE, AEMode
from algorithms.decision_engines.som import Som

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.Sum import Sum
from algorithms.features.impl.Difference import Difference
from algorithms.features.impl.Minimum import Minimum
from algorithms.features.impl.PositionInFile import PositionInFile
from algorithms.features.impl.PositionalEncoding import PositionalEncoding
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.dbscan import DBScan
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.one_minus_x import OneMinusX
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.stream_minimum import StreamMinimum
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.stream_variance import StreamVariance
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.timestamp import Timestamp 
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.persistance import save_to_json

if __name__ == '__main__':

    select_lid_ds_version_number = 0
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]

    # scenarios orderd by training data size asc
    # 0 - 14    
    select_scenario_number = 0
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

    # todo: change this to your base path
    lid_ds_base_path = "/home/grimmer/data"

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

    # features
    ###################
    thread_aware = True
    window_length = 100
    ngram_length = 7
    embedding_size = 10
    #--------------------
    

    ngram_1 = Ngram([IntEmbedding()],True,ngram_length)
    stide = Stide(ngram_1)

    w2v = W2VEmbedding(embedding_size,10,1000,scenario_path,"Models/W2V/",True)
    ngram_2 = Ngram([w2v],True,ngram_length)
    ae = AE(ngram_2, 5, AEMode.LOSS, batch_size=512)

    pe = PathEvilness(scenario_path, force_retrain=True)

    rv = ReturnValue()

    concat = Concat([rv])
    som = Som(concat)


    algorithm_name = "AE"
    config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"

    ###################
    # the IDS
    generate_and_write_alarms = True
    ids = IDS(data_loader=dataloader,
            resulting_building_block=som,
            create_alarms=generate_and_write_alarms,
            plot_switch=True)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    results = ids.performance.get_performance()
    pprint(results)
    
    # enrich results with configuration and save to disk
    results['algorithm'] = algorithm_name
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
    now = datetime.now()  # datetime object containing current date and time    
    dt_string = now.strftime("%Y-%m-%d_%H-%M-%S")  # YY-mm-dd_H-M-S    
    ids.draw_plot(f"results/figure_{config_name}_{dt_string}.png")
