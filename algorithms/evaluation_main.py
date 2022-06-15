import json
from pprint import pprint
from datetime import datetime

import os

from alarm import Alarm

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
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
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


class ArtificialRecording:
    def __init__(self, name, syscalls):
         self.name = name
         self._syscalls = syscalls
         
    def syscalls(self) -> list:
        return self._syscalls
        
    def __repr__(self) -> str:
        return f"ArtificialRecording, Name: {self.name}, Nr. of Systemcalls: {len(self._syscalls)}"

def enough_calls(dict, max): 
    for key in dict.keys():
        if dict[key] < max:
             return False
    return True    

# Take the entrypoint etc. from the existing example_main.py
if __name__ == '__main__':

    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]

    # base path
    lid_ds_base_path = "/media/sf_Masterarbeit/Material"

    for version in lid_ds_version:
        if version=="LID-DS-2019":
            scenario_names = [
                "Bruteforce_CWE-307",
                "CVE-2012-2122",
                "CVE-2014-0160",
                "CVE-2017-7529",
                "CVE-2018-3760",
                "CVE-2019-5418",
                "EPS_CWE-434",
                "PHP_CWE-434",
                "SQL_Injection_CWE-89",
                "ZipSlip"
            ]
        else:           
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
        
        for scenario in scenario_names:
            scenario_path = f"{lid_ds_base_path}/{version}/{scenario}"     
            dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # Results differ, currently BOTH was the best performing

            # Use the best found implementation of STIDE in Grimmers Paper (Window-Length & n-Gram-Length) 
            ###################
            thread_aware = True
            window_length = 1000
            ngram_length = 5
            embedding_size = 10
            #--------------------
    
            intEmbedding = IntEmbedding()
            ngram = Ngram([intEmbedding],True,ngram_length)
            stide = Stide(ngram)

            # IDS
            ###################
            generate_and_write_alarms = True
            ids = IDS(data_loader=dataloader,
                    resulting_building_block=stide,
                    create_alarms=generate_and_write_alarms,
                    plot_switch=False)

            ###################
            pprint("At evaluation:")
            ids.determine_threshold()
            ids.do_detection()
            results = ids.performance.get_performance()
            pprint(results)
    
            # Preparing results
            algorithm_name = "stide"
            config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"
    
            # Enrich results with configuration and save to disk
            results['algorithm'] = algorithm_name
            results['ngram_length'] = ngram_length
            results['window_length'] = window_length
            results['thread_aware'] = thread_aware
            results['config'] = ids.get_config() # Produces strangely formatted Config-Print
            results['scenario'] =  version + "/" + scenario
            result_path = f"results/results_{algorithm_name}_{version}_{scenario}.json"
    
            save_to_json(results, result_path) 

            with open(f"results/alarms_{config_name}_{version}_{scenario}.json", 'w') as jsonfile:
                json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)

            # Extracting Systemcalls from False Alarms
            false_alarm_list = [alarm for alarm in ids.performance.alarms.alarms if not alarm.correct]
            basename_recording_list = set([os.path.basename(false_alarm.filepath) for false_alarm in false_alarm_list])
            false_alarm_recording_list = [recording for recording in dataloader.test_data() if os.path.basename(recording.path) in basename_recording_list]

            data_structure = {}
            for counter in range(len(false_alarm_list)):
                current_false_alarm = false_alarm_list[counter]
                faster_current_basename = os.path.basename(current_false_alarm.filepath)

                for recording in false_alarm_recording_list:
                    if os.path.basename(recording.path) == faster_current_basename:
                        current_recording = recording
                
                #systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= current_false_alarm.first_line_id and systemcall.line_id <= current_false_alarm.last_line_id]
                systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([current_false_alarm.first_line_id - window_length, 0]) and systemcall.line_id <= current_false_alarm.last_line_id] # mit Fensterbetrachtung
                if thread_aware:
            
                    backwards_counter = max([current_false_alarm.first_line_id - window_length, 0])
                    if backwards_counter != 0:
                        thread_id_set = set([systemcall.thread_id() for systemcall in systemcall_list])
      
                        dict = {}
                        for thread in thread_id_set:
                            dict[thread] = 0

                        temp_list = []
                        for x in current_recording.syscalls():
                            temp_list.append(x)
            
                        while(not enough_calls(dict, ngram_length) and backwards_counter != 0):
                            current_call = temp_list[backwards_counter]
                            if current_call.thread_id() in dict.keys():
                                dict[current_call.thread_id()] += 1 
                                systemcall_list.insert(0, current_call)
                            backwards_counter -= 1
                else:
                    systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([current_false_alarm.first_line_id - window_length - ngram_length, 0]) and systemcall.line_id <= current_false_alarm.last_line_id] # mit Fensterbetrachtung
                
                data_structure[os.path.basename(current_false_alarm.filepath) + "_" + '{:0>5}'.format(counter)] = systemcall_list
        
                # MODYFIABLE! Hier kann ich auch einstellen, nur einen Teil der False-Alarms ins Trainig zurückgehen zu lassen.
            all_recordings = []
            for key in data_structure.keys():
                new_recording = ArtificialRecording(key, data_structure[key])
                all_recordings.append(new_recording)

            pprint(len(f"Number of constructed recordings: {all_recordings}"))

            dataloader.set_retraining_data(all_recordings)
    
            ######## New IDS ########################
            ids_retrained = IDS(data_loader=dataloader,
                resulting_building_block=stide,
                plot_switch=False)

            pprint("At evaluation:")
            ids_retrained.determine_threshold()
            ids_retrained.do_detection()
            results_new = ids_retrained.performance.get_performance()
            pprint(results_new)
    
    
            # Preparing second results
            algorithm_name = "stide_retrained"
            config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"
    
            # Enrich results with configuration and save to disk
            results_new['algorithm'] = algorithm_name
            results_new['ngram_length'] = ngram_length
            results_new['window_length'] = window_length
            results_new['thread_aware'] = thread_aware
            results_new['config'] = ids.get_config() # Produces strangely formatted Config-Print
            results_new['scenario'] =  version + "/" + scenario
            result_new_path = f"results/results_{algorithm_name}_{version}_{scenario}.json"
    
            save_to_json(results_new, result_new_path) 

            with open(f"results/alarms_{config_name}_{version}_{scenario}.json", 'w') as jsonfile:
                json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
   
   