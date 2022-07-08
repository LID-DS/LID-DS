import csv
import os
import math
from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.ngram import Ngram

from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    header_exists = False
    out_path = "/home/grimmer/code/LID-DS/results/"
    lid_ds_base_path = "/home/grimmer/data"
    lid_ds_version = "LID-DS-2019"
    scenarios = ["CVE-2017-7529",
                    "Bruteforce_CWE-307",
                    "CVE-2012-2122",
                    "CVE-2014-0160",                                        
                    "CVE-2018-3760",
                    "CVE-2019-5418",
                    "SQL_Injection_CWE-89",
                    "EPS_CWE-434",
                    "PHP_CWE-434",
                    "ZipSlip"]

    window_sizes = [1,10,50,100,300,500,700,900]
    for window_size in window_sizes:
        for scenario_name in scenarios:
            print()
            print(f"at window: {window_size}")
            print(f"at scenario: {scenario_name}")
            print("-------------------------------")
            scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"        
            dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

            ### features
            thread_aware = True
            ngram_length = 7
            enc_size = 10
            ae_hidden_size = int(math.sqrt(ngram_length * enc_size))

            ### building blocks  
            name = SyscallName()
            inte = IntEmbedding(name)
            w2v = W2VEmbedding(word=inte,vector_size=enc_size,window_size=10,epochs=1000)
            ngram = Ngram(feature_list = [w2v],thread_aware = thread_aware,ngram_length = ngram_length)
            ae = AE(ngram,ae_hidden_size,batch_size=256,max_training_time=120,early_stopping_epochs=1000)
            stream_window = StreamSum(ae,True,window_size)

            ### the IDS    
            ids = IDS(data_loader=dataloader,
                    resulting_building_block=stream_window,
                    create_alarms=False,
                    plot_switch=False)

            print("at evaluation:")
            # threshold
            ids.determine_threshold()
            # detection
            results = ids.detect().get_results()
            results["scenario"] = f"{scenario_name}"
            results["stream_window"] = f"{window_size}"
            
            with open(os.path.join(out_path, "ae_window_length_results.csv"), "a") as results_csv:
                fieldnames = ["scenario",
                                "stream_window",
                                "false_positives",
                                "true_positives",
                                "true_negatives",
                                "exploit_count",
                                "detection_rate",
                                "consecutive_false_positives_normal",
                                "consecutive_false_positives_exploits",
                                "recall",
                                "precision_with_cfa",
                                "precision_with_syscalls"]

                writer = csv.DictWriter(results_csv, fieldnames=fieldnames)
                if header_exists is False:
                    writer.writeheader()
                    header_exists = True

                writer.writerow({"scenario": results["scenario"],
                                    "stream_window": results["stream_window"],
                                    "false_positives": results["false_positives"],
                                    "true_positives": results["true_positives"],
                                    "true_negatives": results["true_negatives"],
                                    "exploit_count": results["exploit_count"],
                                    "detection_rate": results["detection_rate"],
                                    "consecutive_false_positives_normal": results["consecutive_false_positives_normal"],
                                    "consecutive_false_positives_exploits": results["consecutive_false_positives_exploits"],
                                    "recall": results["recall"],
                                    "precision_with_cfa": results["precision_with_cfa"],
                                    "precision_with_syscalls":results["precision_with_syscalls"]})
                pprint(results)
