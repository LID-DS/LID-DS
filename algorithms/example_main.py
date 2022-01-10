import json
from pprint import pprint
from torch.nn.modules.activation import Sigmoid

from torch.utils import data
from algorithms.decision_engines.ae import AE, AEMode
from algorithms.decision_engines.lstm import LSTM

from algorithms.decision_engines.stide import Stide
from algorithms.decision_engines.som import Som
from algorithms.features.impl.Maximum import Maximum
from algorithms.features.impl.Sum import Sum
from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.syscalls_in_time_window import SyscallsInTimeWindow
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.MinMaxScaling import MinMaxScaling
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from algorithms.persistance import save_to_json, load_from_json

if __name__ == '__main__':
    # dataloader

    # scenarios orderd by training data size asc
    # 0 - 14
    select_scenario_number = 0
    select_lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]
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
    scenario_path = f"/home/grimmer/data/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}/"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

    # features    
    ngram_length = 7
    embedding_size = 4

    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=10000,
        scenario_path=scenario_path,
        path=f'Models/W2V/',
        force_train=False,
        distinct=True,
        thread_aware=True
    )
    ngram_w2v = Ngram(
        feature_list=[w2v],
        thread_aware=True,
        ngram_length=ngram_length
    )
    stide = Stide(ngram_w2v)
    ae = AE(ngram_w2v,ngram_length*embedding_size,embedding_size, AEMode.LOSS)
    som = Som(ngram_w2v,epochs=500)    
    max = Sum([MinMaxScaling(ae), MinMaxScaling(som), MinMaxScaling(stide)])

    ###################
    # the IDS
    ids = IDS(data_loader=dataloader,
              resulting_building_block=max,
              create_alarms=True,
              plot_switch=False)
   

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    results = ids.performance.get_performance()
    pprint(results)
    
    #print(f"som.cache: {len(som._cache)}")

    # enrich results with configuration and save to disk
    results['config'] = ids.get_config()
    results['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    result_path = 'results/stide.json'
    save_to_json(results, result_path)

    # alarms
    with open('alarms.json', 'w') as jsonfile:
        json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str)

    # plot
    ids.draw_plot()
