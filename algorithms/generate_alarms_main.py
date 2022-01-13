import json
from pprint import pprint
from torch.nn.modules.activation import Sigmoid

from torch.utils import data
from algorithms.decision_engines.ae import AE, AEMode
from algorithms.decision_engines.lstm import LSTM

from algorithms.decision_engines.stide import Stide
from algorithms.decision_engines.som import Som
from algorithms.features import impl
from algorithms.features.impl import concat
from algorithms.features.impl.Maximum import Maximum
from algorithms.features.impl.Sum import Sum
from algorithms.features.impl.dbscan import DBScan
from algorithms.features.impl.dgram import Dgram
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.stream_product import StreamProduct
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.syscalls_in_time_window import SyscallsInTimeWindow
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.MinMaxScaling import MinMaxScaling
from algorithms.features.impl.repetition_remover import RepetitionRemover
from algorithms.features.impl.syscall_start_end_times import StartEndTimes
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.decision_engines.scg import SystemCallGraph

from algorithms.persistance import save_to_json, load_from_json

if __name__ == '__main__':

    # scenarios orderd by training data size asc
    # 0 - 14
    select_lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021_v3"
    ]

    select_scenario_number = 4
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
    scenario_path = f"/home/grimmer/data/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

    # features
    ###################
   
    dgram = Dgram([IntEmbedding()],True)    
    scg = SystemCallGraph(dgram,True,False)
    scg_sum = StreamSum(scg,True,10)
    scg_min_max = MinMaxScaling(scg_sum)

    stide = Stide(dgram,100)
    stide_min_max = MinMaxScaling(stide)

    w2v = W2VEmbedding(
        vector_size=5,
        window_size=10,
        epochs=10000,
        scenario_path=scenario_path,
        path=f'Models/W2V/',
        force_train=False,
        distinct=True,
        thread_aware=True
    )
    som_ngram = Ngram([w2v],True,7)
    som = Som(som_ngram)
    som_min_max = MinMaxScaling(som)

    sum = Sum([scg_min_max,stide_min_max,som_min_max])
    sum_w = StreamSum(sum,True,10)

    config_name = "sum_scg_stide_som"

    ###################
    # the IDS
    ids = IDS(data_loader=dataloader,
              resulting_building_block=sum_w,
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
    with open(f"results/alarms_{config_name}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
        json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)

    # plot
    ids.draw_plot()
