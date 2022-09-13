import os
import sys

from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.one_hot_encoding import OneHotEncoding

from algorithms.ids import IDS
from algorithms.persistance import save_to_mongo

from algorithms.decision_engines.ae import AE

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding


if __name__ == '__main__':

    lid_ds_version_number = 0
    lid_ds_version = [
        "LID-DS-2019",
        "LID-DS-2021"
    ]

    # scenarios ordered by training data size asc
    # 0 - 14
    scenario_names = [
        # "CVE-2017-7529",
        # "CVE-2014-0160",
        # "CVE-2012-2122",
        # "Bruteforce_CWE-307",
        # "CVE-2020-23839",
        # "CWE-89-SQL-injection",
        # "PHP_CWE-434",
        "ZipSlip",
        "CVE-2018-3760",
        # "CVE-2020-9484",
        "EPS_CWE-434",
        "CVE-2019-5418",
        # "Juice-Shop",
        # "CVE-2020-13942",
        # "CVE-2017-12635_6"
    ]

    ###################
    # feature config:
    ngram_length = 7
    w2v_size = 5
    thread_aware = True

    # run config
    scenario_range = scenario_names[0:1]
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

    for scenario_number in range(0, len(scenario_range)):
        scenario_path = os.path.join(lid_ds_base_path,
                                     lid_ds_version[lid_ds_version_number],
                                     scenario_range[scenario_number])
        dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)
        name = SyscallName()
        w2v = W2VEmbedding(epochs=500,
                           word=name,
                           vector_size=w2v_size,
                           window_size=ngram_length
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
        # ae_tf = AE_TF(
            # input_vector=ngram,
            # epochs=10000
        # )

        sum = StreamSum(ae, False,10)

        ###################
        # the IDS
        ids = IDS(data_loader=dataloader,
                  resulting_building_block=sum,
                  create_alarms=False,
                  plot_switch=False)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        results = ids.detect().get_results()
        pprint(results)

        # enrich results with configuration and save to disk
        results['algorithm'] = "AE"
        results['ngram_length'] = ngram_length
        results['embedding'] = "OHE"
        results['thread_aware'] = thread_aware
        results['config'] = ids.get_config()
        results['scenario'] = scenario_range[scenario_number]
        results['dataset'] = lid_ds_version[lid_ds_version_number]
        save_to_mongo(results)
