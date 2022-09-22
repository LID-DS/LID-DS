"""
    Example main for AE IDS
"""
import os
import sys

from pprint import pprint

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.syscall_name import SyscallName
# from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.one_hot_encoding import OneHotEncoding

from algorithms.ids import IDS
from algorithms.persistance import save_to_mongo

from algorithms.decision_engines.ae import AE

from algorithms.features.impl.ngram import Ngram


if __name__ == '__main__':

    LID_DS_VERSION_NUMBER = 0
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
        # "SQL_Injection_CWE-89",
        # "PHP_CWE-434",
        # "CVE-2019-5418",
        # "CVE-2018-3760",
        "EPS_CWE-434",
        "ZipSlip",
        # "CVE-2020-9484",
        # "Juice-Shop",
        # "CVE-2020-13942",
        # "CVE-2017-12635_6"
    ]

    ###################
    # feature config:
    # zu testen:
    # NGRAM_LENGTH: 3, 5, 7
    # embedding: ohe, w2v 3, 5
    NGRAM_LENGTH = [5]
    W2V_SIZE = [5]
    THREAD_AWARE = True
    STREAM_SUM = [1]

    # run config
    scenario_range = scenario_names
    ###################

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError as e:
            raise ValueError("No LID-DS Base Path given. "
                             "Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE") from e

    for ngram_length in NGRAM_LENGTH:
        for window in STREAM_SUM:
            for w2v_size in W2V_SIZE:
                for scenario_number, scenario in enumerate(scenario_range):
                    scenario_path = os.path.join(lid_ds_base_path,
                                                 lid_ds_version[LID_DS_VERSION_NUMBER],
                                                 scenario)
                    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)
                    name = SyscallName()
                    # embedding = W2VEmbedding(epochs=500,
                                             # word=name,
                                             # vector_size=w2v_size,
                                             # window_size=ngram_length
                                             # )

                    embedding = OneHotEncoding(name)

                    ngram = Ngram(feature_list=[embedding],
                                  thread_aware=THREAD_AWARE,
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

                    stream_sum = StreamSum(ae, False, window)

                    ###################
                    # the IDS
                    ids = IDS(data_loader=dataloader,
                              resulting_building_block=stream_sum,
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
                    # results['embedding_size'] = w2v_size
                    results['thread_aware'] = THREAD_AWARE
                    results['stream_sum'] = window
                    results['config'] = ids.get_config()
                    results['scenario'] = scenario_range[scenario_number]
                    results['dataset'] = lid_ds_version[LID_DS_VERSION_NUMBER]
                    save_to_mongo(results)
