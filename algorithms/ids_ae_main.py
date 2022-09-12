import os
import sys
import math

import torch

from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.ids import IDS

from algorithms.decision_engines.ae import AE
from algorithms.decision_engines.aetf import AE_TF
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.w2v_embedding import W2VEmbedding

if __name__ == '__main__':

    # lid_ds_version:
    #    "LID-DS-2019"
    #    "LID-DS-2021"

    # scenarios ordered by training data size asc    
    # 
    #    "CVE-2017-7529",
    #    "CVE-2014-0160",
    #    "CVE-2012-2122",
    #    "Bruteforce_CWE-307",
    #    "CVE-2020-23839",
    #    "CWE-89-SQL-injection",
    #    "PHP_CWE-434",
    #    "ZipSlip",
    #    "CVE-2018-3760",
    #    "CVE-2020-9484",
    #    "EPS_CWE-434",
    #    "CVE-2019-5418",
    #    "Juice-Shop",
    #    "CVE-2020-13942",
    #    "CVE-2017-12635_6"

    # feature config:
    ngram_length = 7
    w2v_size = 10
    w2v_window_size = 10
    thread_aware = True

    # getting the LID-DS base path, version and scenario from argument
    try:        
        lid_ds_base_path = sys.argv[1]
        lid_ds_version = sys.argv[2]
        scenario_name = sys.argv[3]
    except:
        print(f"Error, call with:\n> python3 {sys.argv[0]} lid_ds_base_path lid_ds_version scenario_name")
        exit()        

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"        

    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

    # features
    ###################
    name = SyscallName()
    w2v = W2VEmbedding(epochs=500,
                        word=name,
                        vector_size=w2v_size,
                        window_size=w2v_window_size
                        )

    ohe = OneHotEncoding(name)

    ngram = Ngram(feature_list=[ohe],
                    thread_aware=thread_aware,
                    ngram_length=ngram_length
                    )
    
    # pytorch impl.
    ae = AE(
        input_vector=ngram
    )

    # keras/tf impl.
    ae_tf = AE_TF(
        input_vector=ngram,
        epochs=10000
    )


    sum = StreamSum(ae_tf, False,10)

    ###################
    # the IDS
    ids = IDS(data_loader=dataloader,
                resulting_building_block=sum,
                create_alarms=False,
                plot_switch=True)

    print("at evaluation:")
    # threshold
    ids.determine_threshold_and_plot()
    # detection
    # performance = ids.detect_parallel()
    performance = ids.detect()
    results = performance.get_results() 
    
    pprint(results)
    ids.draw_plot()
    

    # enrich results with configuration and save to disk
    results['algorithm'] = "AE_TF"
    results['ngram_length'] = ngram_length
    results['w2v_size'] = w2v_size
    results['thread_aware'] = thread_aware
    results['config'] = ids.get_config()
    results['scenario'] = scenario_name
    result_path = 'results/results_ae.json'
