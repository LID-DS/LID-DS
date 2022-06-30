import csv
from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.decision_engines.stide import Stide
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from algorithms.data_preprocessor import DataPreprocessor
from pprint import pprint
import os
import argparse


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Saving Stide Performance to csv.')

    parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS base path')
    parser.add_argument('-o', dest='output_path', action='store', type=str, required=True,
                        help='output path for performance')

    args = parser.parse_args()

    # lists of config parameters to iterate through
    THREAD_AWARE = [True, False]
    N_GRAM_PARAMS = [3, 5, 8]
    WINDOW_LENGTH_PARAMS = [100, 1000, 10000]

    SCENARIO_NAMES = ["Bruteforce_CWE-307",
                      "CVE-2012-2122",
                      "CVE-2014-0160",
                      "CVE-2017-7529",
                      "CVE-2017-12635_6",
                      "CVE-2018-3760",
                      "CVE-2019-5418",
                      "CVE-2020-9484",
                      "CVE-2020-13942",
                      "CVE-2020-23839",
                      "CWE-89-SQL-Injection",
                      "CWE-89-SQL-injection",
                      "EPS_CWE-434",
                      "Juice-Shop",
                      "PHP_CWE-434",
                      "ZipSlip"]

    syscall_feature_list = [SyscallToInt(),
                            ThreadIDExtractor()]

    header_exists = False

    # data loader for scenario
    for name in SCENARIO_NAMES:
        dataloader = DataLoader(os.path.join(args.base_path, name))

        for flag in THREAD_AWARE:
            for ngram_config in N_GRAM_PARAMS:
                for window_config in WINDOW_LENGTH_PARAMS:

                    print('Running STIDE algorithm with config:')
                    print(f'   Scenario: {name}')
                    print(f'   Thread Aware: {flag}')
                    print(f'   n_gram Size: {ngram_config}')
                    print(f'   Window Size: {window_config}')

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
                    ids.detect()
                    performance_dict = ids.performance.get_performance()
                    performance_dict["scenario"] = f"{name}"
                    performance_dict["thread_aware"] = f"{flag}"
                    performance_dict["n_gram"] = f"{ngram_config}"
                    performance_dict["window_length"] = f"{window_config}"
                    # pprint(perf_dict)

                    with open(os.path.join(args.output_path, "performance.csv"), "a") as performance_csv:
                        fieldnames = ["scenario",
                                      "thread_aware",
                                      "n_gram",
                                      "window_length",
                                      "false_positives",
                                      "true_positives",
                                      "true_negatives",
                                      "alarm_count",
                                      "exploit_count",
                                      "detection_rate",
                                      "consecutive_false_positives_normal",
                                      "consecutive_false_positives_exploits",
                                      "recall",
                                      "precision_with_cfa",
                                      "precision_with_syscalls"]

                        writer = csv.DictWriter(performance_csv, fieldnames=fieldnames)
                        if header_exists is False:
                            writer.writeheader()
                            header_exists = True

                        writer.writerow({"scenario": performance_dict["scenario"],
                                         "thread_aware": performance_dict["thread_aware"],
                                         "n_gram": performance_dict["n_gram"],
                                         "window_length": performance_dict["window_length"],
                                         "false_positives": performance_dict["false_positives"],
                                         "true_positives": performance_dict["true_positives"],
                                         "true_negatives": performance_dict["true_negatives"],
                                         "alarm_count": performance_dict["alarm_count"],
                                         "exploit_count": performance_dict["exploit_count"],
                                         "detection_rate": performance_dict["detection_rate"],
                                         "consecutive_false_positives_normal": performance_dict["consecutive_false_positives_normal"],
                                         "consecutive_false_positives_exploits": performance_dict["consecutive_false_positives_exploits"],
                                         "recall": performance_dict["recall"],
                                         "precision_with_cfa": performance_dict["precision_with_cfa"],
                                         "precision_with_syscalls":performance_dict["precision_with_syscalls"]})



