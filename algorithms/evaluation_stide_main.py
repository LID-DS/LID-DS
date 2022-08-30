import os
import sys
import json
from multiprocessing import cpu_count
from pprint import pprint
from tqdm.contrib.concurrent import process_map
from functools import reduce
from time import time
from argparse import ArgumentParser

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.ids import IDS
from algorithms.persistance import save_to_json
from dataloader.dataloader_factory import dataloader_factory 
from dataloader.direction import Direction


class FalseAlertContainer:
    def __init__(self, alarm, alarm_recording_list, window_length, ngram_length, thread_aware) -> None:
        self.alarm = alarm
        self.alarm_recording_list = alarm_recording_list
        self.window_length = window_length
        self.ngram_length = ngram_length
        self.thread_aware = thread_aware
    
    
class FalseAlertResult:
    def __init__(self, name, syscalls) -> None:
        self.name = name # Hier was mit der Zeit machen sonst bekomme ich wieder Probleme.
        self.syscalls = syscalls
        self.structure = {name: syscalls}
        
    def add(left: 'FalseAlertResult', right: 'FalseAlertResult') -> 'FalseAlertResult':
        result = FalseAlertResult(right.name, right.syscalls)
        result.structure = left.structure        
        result.structure[right.name] = right.syscalls

        return result
    
    def __repr__(self) -> str:
        return f"FalseAlertResult: Name: {self.name}, Structure: {self.structure}"
        
# Brauche ich um die Systemcalls dem Trainingsdatensatz hinzuzufügen
class ArtificialRecording:  
    def __init__(self, name, syscalls):
         self.name = name
         self._syscalls = syscalls
         
    def syscalls(self) -> list:
        return self._syscalls
        
    def __repr__(self) -> str:
        return f"ArtificialRecording, Name: {self.name}, Nr. of Systemcalls: {len(self._syscalls)}"

# Benutze ich um festzustellen, wann ich genügend Systemcalls für einen False-Alert habe
def enough_calls(dict, max):   
    for key in dict.keys():
        if dict[key] < max:
             return False
    return True    

def construct_Syscalls(container: FalseAlertContainer) -> FalseAlertResult:
    alarm = container.alarm
    alarm_recording_list = container.alarm_recording_list
    
    faster_current_basename = os.path.basename(alarm.filepath)
    for recording in alarm_recording_list:
        if os.path.basename(recording.path) == faster_current_basename:
            current_recording = recording
    
    
    systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([alarm.first_line_id - container.window_length, 0]) and systemcall.line_id <= alarm.last_line_id] 
    
    if container.thread_aware:
            
        backwards_counter = max([alarm.first_line_id - container.window_length -1, 0]) 
        if backwards_counter != 0:
            thread_id_set = set([systemcall.thread_id() for systemcall in systemcall_list])


            dict = {}
            for thread in thread_id_set:
                dict[thread] = 0
    
            temp_list = []
            for x in current_recording.syscalls():
                temp_list.append(x)
                if x.line_id == alarm.last_line_id:
                    break 
           
            temp_list.reverse() 
                
            while(not enough_calls(dict, container.ngram_length) and backwards_counter != 0):
                current_call = None
                for call in temp_list:
                    if call.line_id == backwards_counter:
                        current_call = call  
                        break  
                    
                if current_call is None:
                    backwards_counter -=1 
                    continue
                    
                if current_call.thread_id() in dict.keys() and dict[current_call.thread_id()] < container.ngram_length:
                    dict[current_call.thread_id()] += 1 
                    systemcall_list.insert(0, current_call)
                        
                backwards_counter -= 1
                
    else:

        systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([alarm.first_line_id - container.window_length - container.ngram_length, 0]) and systemcall.line_id <= alarm.last_line_id] # mit Fensterbetrachtung
        
        
    result = FalseAlertResult(f"{os.path.basename(current_recording.path)}_{str(round(time()*1000))[-5:]}", systemcall_list)
    result.structure[result.name] = result.syscalls
        
    return result  


# Argument Parser für bessere die Nutzbarkeit eines einzelnen Scripts, welches dann auf dem Cluster gecallt wird.
def parse_cli_arguments(): 
    parser = ArgumentParser(description='Playing Back False-Positives Pipeline')
    parser.add_argument('--version', '-v', choices=['LID-DS-2019', 'LID-DS-2021'], required=True, help='Which version of the LID-DS?')
    parser.add_argument('--scenario', '-s', choices=['Bruteforce_CWE-307',
                                                     'CVE-2012-2122',
                                                     'CVE-2014-0160',
                                                     'CVE-2017-7529',
                                                     'CVE-2017-12635_6',
                                                     'CVE-2018-3760',
                                                     'CVE-2019-5418',
                                                     'CVE-2020-9484',
                                                     'CVE-2020-13942',
                                                     'CVE-2020-23839',
                                                     'CWE-89-SQL-injection',
                                                     "SQL_Injection_CWE-89",
                                                     'EPS_CWE-434',
                                                     'Juice-Shop',
                                                     'PHP_CWE-434',
                                                     'ZipSlip'], required=True, help='Which scenario of the LID-DS?')
    parser.add_argument('--play_back_count_alarms', '-p' , choices=['1', '2', '3', 'all'], default='all', help='Number of False Alarms that shall be played back or all.')
    parser.add_argument('--results', '-r', default='results', help='Path for the results of the evaluation')
    parser.add_argument('--base-path', '-b', default='/home/sc.uni-leipzig.de/lz603fxao/Material', help='Base path of the LID-DS')
    parser.add_argument('--to-dataset-playing-back', '-t', default = 'training', choices=['training', 'validation'], help='Decides in which dataset the false-positives will be played back.')
    parser.add_argument('--freeze-on-retraining', '-f', default='False', choices=['True', 'False'], help='After the retraining of the IDS, will you freeze the original threshold or calculate a new one?')


    return parser.parse_args()


# Startpunkt
if __name__ == '__main__':
    
    args = parse_cli_arguments()
    
    # Check ob die Kombination vorhanden ist.
    if args.version == 'LID-DS-2019':
        if args.scenario in ['CWE-89-SQL-injection', 'CVE-2020-23839', 'CVE-2020-9484', 'CVE-2020-13942' , 'Juice-Shop' , 'CVE-2017-12635_6']:
            sys.exit('This combination of LID-DS Version and Scenario aren\'t available.')
    
    if args.to_dataset_playing_back == 'validation':
        if args.freeze_on_retraining == 'True':
            sys.exit('This combination can\'t be played since we want to play back the examples in the validation set. Therefore we MUST NOT freeze the threshold.')
    
    pprint("Performing Host-based Intrusion Detection with STIDE:")
    pprint(f"Version: {args.version}") 
    pprint(f"Scenario: {args.scenario}")
    pprint(f"Number of maximal played back false alarms: {args.play_back_count_alarms}")
    pprint(f"Results path: {args.results}")
    pprint(f"Base path: {args.base_path}")
    pprint(f"Playing back into {args.to_dataset_playing_back} datatset.")
    pprint(f"Treshold freezing on seconds IDS: {args.freeze_on_retraining}")
        
    scenario_path = f"{args.base_path}/{args.version}/{args.scenario}"     
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # Results differ, currently BOTH was the best performing
    
    #--------------------
    # Choosing best configs in M. Grimmers Paper.
    ####################
    thread_aware = True
    window_length = 1000
    ngram_length = 5
        
    intEmbedding = IntEmbedding()
    ngram = Ngram([intEmbedding], thread_aware, ngram_length)
    decision_engine = Stide(ngram, window_length)

    # IDS
    ###################
    generate_and_write_alarms = True
    ids = IDS(data_loader=dataloader,
            resulting_building_block=decision_engine,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)
    
    ###################
    pprint("At evaluation:")
    ids.determine_threshold()   
    performance = ids.detect_parallel()
    pprint(performance)
    
    results = performance.get_results()
    pprint(results)
    
    # Preparing results
    config_name = f"algorithm_stide_n_{ngram_length}_w_{window_length}_t_{thread_aware}"

    # Enrich results with configuration
    results['algorithm'] = 'stide'
    results['ngram_length'] = ngram_length
    results['window_length'] = window_length
    results['thread_aware'] = thread_aware
    results['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results['scenario'] =  args.version + "/" + args.scenario
    result_path = f"{args.results}/results_stide_{args.version}_{args.scenario}.json"

    # Saving results
    save_to_json(results, result_path) 
    with open(f"{args.results}/alarms_{config_name}_{args.version}_{args.scenario}.json", 'w') as jsonfile:
        json.dump(performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
        
    # ---------------------------------------------------------------------------------------------------------#    
        
    # Extracting Systemcalls from False Alarms
    false_alarm_list = [alarm for alarm in performance.alarms.alarm_list if not alarm.correct]
    
    # Stop all of this if we didn't found any false alarms. Empty lists are considered false.
    if not false_alarm_list:
        sys.exit('The decision engine didn\'t found any false alarms which it could play back. Stopping here.')
    
    # Collect all corresponding recordings 
    basename_recording_list = set([os.path.basename(false_alarm.filepath) for false_alarm in false_alarm_list])
    false_alarm_recording_list = [recording for recording in dataloader.test_data() if os.path.basename(recording.path) in basename_recording_list]
   
   
    containerList = []
    counter = 0
    for alarm in false_alarm_list: 
        if args.play_back_count_alarms != 'all' and counter == int(args.play_back_count_alarms):
            break
        containerList.append(FalseAlertContainer(alarm, false_alarm_recording_list, window_length, ngram_length, thread_aware))
        counter += 1    
    
    pprint("Playing back false positive alarms:")
    if sys.platform in ['win32', 'cygwin']:
        max_workers = 4 # Musste das begrenzen da mir sonst alles abschmierte
    else:
        max_workers = min(32, cpu_count() + 4)
    
    false_alarm_results = process_map(construct_Syscalls, containerList, chunksize = 1, max_workers=max_workers)
    final_playback = reduce(FalseAlertResult.add, false_alarm_results)
    
    
    # MODYFIABLE! Hier kann ich auch einstellen, nur einen Teil der False-Alarms ins Training zurückgehen zu lassen.
    all_recordings = []  
    counter = 0
    
    # Iteriere durch alle False-Alarms und nutze die jeweiligen SystemCalls. 
    for key in final_playback.structure.keys():
        new_recording = ArtificialRecording(key, final_playback.structure[key])
        all_recordings.append(new_recording)
        counter += 1
    
    if not all_recordings:
        exit(f'Percentage of {args.play_back_percentage} playing back alarms lead to playing back zero false alarms. Program stops.')


    # Loading new examples
    if args.to_dataset_playing_back == 'training':
        dataloader.set_retraining_data(all_recordings) # Fügt die neuen Trainingsbeispiele als zusätzliches Training ein.
    elif args.to_dataset_playing_back == 'validation':
        dataloader.set_revalidation_data(all_recordings) # Fügt die neuen Trainingsbeispiele bei den Validierungsdaten ein.
    else: 
        sys.exit('Unknown dataset where this shall be played back.')


    ##### New BBs ############
    thread_aware = True
    window_length = 1000
    ngram_length = 5
        
    intEmbedding = IntEmbedding()
    ngram = Ngram([intEmbedding], thread_aware, ngram_length)
    decision_engine = Stide(ngram, window_length)

    ######## New IDS ########################
    ids_retrained = IDS(data_loader=dataloader,
        resulting_building_block=decision_engine,
        plot_switch=False,
        create_alarms=True)
    
    pprint("At evaluation:")
    # Unloading datasets and managing thresholds        
    if args.to_dataset_playing_back == 'training':
        dataloader.unload_retraining_data()
        if args.freeze_on_retraining == 'True':
            pprint(f"Freezing Threshold on: {ids.threshold}")
            ids_retrained.threshold = ids.threshold
        else: 
            ids_retrained.determine_threshold()
      
    elif args.to_dataset_playing_back == 'validation':
        if args.freeze_on_retraining == 'True':
            sys.exit('This combination shouldnt be possible. Abborting.')
        else:
            ids_retrained.determine_threshold() 
            dataloader.unload_revalidation_data()
    else:
        sys.exit('Unknown dataset where this shall be played back.')
      
      
    performance_new = ids_retrained.detect_parallel()
    pprint(performance_new) 
    
    results_new = performance_new.get_results()
    pprint(results_new)

    # Preparing second results
    algorithm_name = f"stide_retrained"
    config_name = f"algorithm_{algorithm_name}_p_{args.play_back_count_alarms}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"

    # Enrich results with configuration 
    results_new['algorithm'] = algorithm_name
    results_new['play_back_count_alarms']= args.play_back_count_alarms
    results_new['ngram_length'] = ngram_length
    results_new['window_length'] = window_length
    results_new['thread_aware'] = thread_aware
    results_new['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results_new['scenario'] =  args.version + "/" + args.scenario
    result_new_path = f"{args.results}/results_{algorithm_name}_p_{args.play_back_count_alarms}_{args.version}_{args.scenario}.json"

    # Save results
    save_to_json(results_new, result_new_path) 
    with open(f"{args.results}/alarms_{config_name}_{args.version}_{args.scenario}.json", 'w') as jsonfile:
        json.dump(performance_new.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
   
   