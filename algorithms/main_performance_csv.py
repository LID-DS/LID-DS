import csv
from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.decision_engines.stide import Stide
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from dataloader.data_preprocessor import DataPreprocessor
from pprint import pprint
import os


if __name__ == '__main__':

    dataset_folder_path = "/home/eschulze/LID-DS-2021/"

    # lists of config parameters to iterate through
    THREAD_AWARE = [True, False]
    N_GRAM_PARAMS = [3, 5, 8]
    WINDOW_LENGTH_PARAMS = [100, 1000, 10000]

    SCENARIO_NAMES = ["CVE-2017-7529"]

    syscall_feature_list = [SyscallToInt(),
                            ThreadIDExtractor()]

    # data loader for scenario
    for name in SCENARIO_NAMES:
        dataloader = DataLoader(os.path.join(dataset_folder_path, name))

        for flag in THREAD_AWARE:
            for ngram_config in N_GRAM_PARAMS:
                for window_config in WINDOW_LENGTH_PARAMS:
                    stream_feature_list = [StreamNgramExtractor(feature_list=[SyscallToInt],
                                                                thread_aware=flag,
                                                                ngram_length=ngram_config)]

                    dataprocessor = DataPreprocessor(dataloader,
                                                     syscall_feature_list,
                                                     stream_feature_list)
                    # decision engine (DE)
                    stide = Stide(window_length=window_config)

                    # define the used features
                    ids = IDS(data_loader=dataloader,
                              data_preprocessor=dataprocessor,
                              decision_engine=stide,
                              plot_switch=False)

                    ids.train_decision_engine()
                    ids.determine_threshold()
                    ids.do_detection()
                    performance_dict = ids.performance.get_performance()
                    # pprint(perf_dict)

                    with open("performance.csv", 'a') as performance_csv:
                        writer = csv.writer(performance_csv)
                        writer.writerow([f"{name} / ta? {flag}, n_gram: {ngram_config}, window: {window_config}"])
                        for key, value in performance_dict.items():
                            writer.writerow([key, value])



