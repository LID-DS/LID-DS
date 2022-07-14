import json
from pprint import pprint
from datetime import datetime

import os
import sys


from argparse import ArgumentParser

from numpy import vectorize
import torch
import numpy
import random
#from algorithms.decision_engines.ae import AE, AEMode
#from algorithms.decision_engines.som import Som
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.select import Select
#from algorithms.features.impl.Sum import Sum
#from algorithms.features.impl.Difference import Difference
#from algorithms.features.impl.Minimum import Minimum
#from algorithms.features.impl.PositionInFile import PositionInFile
#from algorithms.features.impl.PositionalEncoding import PositionalEncoding
#from algorithms.features.impl.concat import Concat
#from algorithms.features.impl.dbscan import DBScan
from algorithms.features.impl.int_embedding import IntEmbedding
#from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.ngram import Ngram
#from algorithms.features.impl.one_minus_x import OneMinusX
#from algorithms.features.impl.path_evilness import PathEvilness
#from algorithms.features.impl.return_value import ReturnValue
#from algorithms.features.impl.stream_average import StreamAverage
#from algorithms.features.impl.stream_maximum import StreamMaximum
#from algorithms.features.impl.stream_minimum import StreamMinimum
#from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.syscall_name import SyscallName
#from algorithms.features.impl.stream_variance import StreamVariance
from algorithms.features.impl.w2v_embedding import W2VEmbedding
#from algorithms.features.impl.timestamp import Timestamp 
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.persistance import save_to_json
from copy import deepcopy
from tqdm.contrib.concurrent import process_map
from functools import reduce
from algorithms.performance_measurement import Performance
from tqdm import tqdm
from time import time
from algorithms.decision_engines.mlp import MLP


class FalseAlertContainer:
    def __init__(self, alarm, alarm_recording_list, window_length, ngram_length) -> None:
        self.alarm = alarm
        self.alarm_recording_list = alarm_recording_list
        self.window_length = window_length
        self.ngram_length = ngram_length
    
    
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


class Container:
    def __init__(self, ids, recording):
        self.ids = ids
        self. recording = recording
        
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

def calculate(struct: Container) -> Performance:
    # Copy the whole IDS with its building blocks
    working_copy = deepcopy(struct.ids)
    # Calculate the performance on the current recording
    performance = working_copy.detect_on_recording(struct.recording)
    return performance


def construct_Syscalls(container: FalseAlertContainer) -> FalseAlertResult:
    alarm = container.alarm
    alarm_recording_list = container.alarm_recording_list
    
    faster_current_basename = os.path.basename(alarm.filepath)
    for recording in alarm_recording_list:
        if os.path.basename(recording.path) == faster_current_basename:
            current_recording = recording
    
    
    systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([alarm.first_line_id - container.window_length, 0]) and systemcall.line_id <= alarm.last_line_id] 
    
    if thread_aware:
            
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
    parser.add_argument('--algorithm', '-a', choices=['stide',
                                                      'mlp',
                                                      'ae',
                                                      'som'], required=True, help='Which algorithm shall perform the detection?')
    parser.add_argument('--play_back_count_alarms', '-p' , choices=['1', '2', '3', 'all'], default='all', help='Number of False Alarms that shall be played back or all.')
    parser.add_argument('--results', '-r', default='results', help='Path for the results of the evaluation')
    parser.add_argument('--base-path', '-b', default='/work/user/lz603fxao/Material', help='Base path of the LID-DS')
    parser.add_argument('--config', '-c', choices=['0', '1', '2'], default='0', help='Configuration of the MLP which will be used in this evaluation')


    return parser.parse_args()


# Startpunkt
if __name__ == '__main__':
    
    args = parse_cli_arguments()
    
    # Check ob die Kombination vorhanden ist.
    if args.version == 'LID-DS-2019':
        if args.scenario in ['CWE-89-SQL-injection', 'CVE-2020-23839', 'CVE-2020-9484', 'CVE-2020-13942' , 'Juice-Shop' , 'CVE-2017-12635_6']:
            sys.exit('This combination of LID-DS Version and Scenario aren\'t available.')
    
    
    pprint("Performing Host-based Intrusion Detection with:")
    pprint(f"Version: {args.version}") 
    pprint(f"Scenario: {args.scenario}")
    pprint(f"Algorithm: {args.algorithm}")
    pprint(f"Number of maximal played back false alarms: {args.play_back_count_alarms}")
    pprint(f"Results path: {args.results}")
    pprint(f"Base path: {args.base_path}")
    
    scenario_path = f"{args.base_path}/{args.version}/{args.scenario}"     
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # Results differ, currently BOTH was the best performing
    
    #--------------------
        
    # Stopping Randomness
    torch.manual_seed(0)
    random.seed(0)
    numpy.random.seed(0)
    torch.use_deterministic_algorithms(True)
        
    # Configuration of chosen decision engines. Choosing best configs in M. Grimmers Paper.
    ####################
    
    # STIDE
    if args.algorithm == 'stide':
        thread_aware = True
        window_length = 1000
        ngram_length = 5
        embedding_size = 10
        
        intEmbedding = IntEmbedding()
        ngram = Ngram([intEmbedding], thread_aware, ngram_length)
        decision_engine = Stide(ngram, window_length)

    # MLP 
    elif args.algorithm == 'mlp':
        
        settings_dict = {} # Enthält die Konfig-Infos
        if args.config == '0':
            
            ##################################### Config 0 ######################################### 
            
            # Settings
            ngram_length = 5
            w2v_vector_size = 5
            w2v_window_size = 10
            thread_aware = True
            hidden_size = 64
            hidden_layers = 3
            batch_size = 256
            w2v_epochs = 1000
            learning_rate = 0.003
            window_length = 10

            settings_dict['ngram_length'] = ngram_length
            settings_dict['w2v_vector_size'] = w2v_vector_size
            settings_dict['w2v_window_size'] = w2v_window_size
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['w2v_epochs'] = w2v_epochs
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length

            # Building Blocks
            inte = IntEmbedding()

            w2v = W2VEmbedding(word=inte,
                           vector_size=w2v_vector_size,
                           window_size=w2v_window_size,
                           epochs=w2v_epochs,
                           thread_aware=thread_aware)
            
            ohe = OneHotEncoding(inte)

            ngram = Ngram([w2v], thread_aware, ngram_length + 1) 

            select = Select(ngram, start = 0, end = (w2v_vector_size * ngram_length)) 

            mlp = MLP(select,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )
            
            decision_engine = StreamSum(mlp, thread_aware, window_length)
        
        ##################################### Config 1 ######################################### 
        elif args.config == '1':
            
            # Settings
            ngram_length = 3
            w2v_vector_size = 8
            w2v_window_size = 15
            thread_aware = True
            hidden_size = 32
            hidden_layers = 4
            batch_size = 256
            w2v_epochs = 1000
            learning_rate = 0.003
            window_length = 100       
            
            
            settings_dict['ngram_length'] = ngram_length
            settings_dict['w2v_vector_size'] = w2v_vector_size
            settings_dict['w2v_window_size'] = w2v_window_size
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['w2v_epochs'] = w2v_epochs
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length
            
            
            # Building Blocks

            inte = IntEmbedding()

            w2v = W2VEmbedding(word=inte,
                           vector_size=w2v_vector_size,
                           window_size=w2v_window_size,
                           epochs=w2v_epochs,
                           thread_aware=thread_aware)
            
            ohe = OneHotEncoding(inte)

            ngram = Ngram([w2v], thread_aware, ngram_length + 1) 

            select = Select(ngram, start = 0, end = (w2v_vector_size * ngram_length)) 

            mlp = MLP(select,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )
            
            decision_engine = StreamSum(mlp, thread_aware, window_length)
        
        ##################################### Config 2 ######################################### 
        elif args.config == '2':
            
            # Settings
            ngram_length = 7
            thread_aware = True
            hidden_size = 64
            hidden_layers = 3
            batch_size = 256
            learning_rate = 0.003
            window_length = 5

            
            settings_dict['ngram_length'] = ngram_length
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length
            
            # Building Blocks
            inte = IntEmbedding()
            
            ohe = OneHotEncoding(inte)
            
            ngram_ohe = Ngram([ohe], thread_aware, ngram_length + 1)
            
            select_ohe = Select(ngram_ohe, 0, (ngram_length * 23)) # TODO: 23 works only for 2019:2017 rn
            
            mlp = MLP(select_ohe,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )   
    
            decision_engine = StreamSum(mlp, thread_aware, window_length)
            
        else:
            exit('Unknown configuration of MLP. Exiting.')
        
        
    # AE - TODO
    elif args.algorithm == 'ae':
        pass
    # SOM - TODO
    elif args.algorithm == 'som':
        pass
    
    
    
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
    results = performance.get_results()
    pprint(results)
    
    # Preparing results
    
    if args.algorithm == 'stide':
        config_name = f"algorithm_{args.algorithm}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"
    else: 
        config_name = f"algorithm_{args.algorithm}_n_{ngram_length}_t_{thread_aware}"
    
    
    # Enrich results with configuration
    results['algorithm'] = args.algorithm
    for key in settings_dict.keys():
        results[key] = settings_dict[key]
    # results['ngram_length'] = ngram_length
    # results['window_length'] = window_length 
    # results['thread_aware'] = thread_aware
    results['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results['scenario'] =  args.version + "/" + args.scenario
    result_path = f"{args.results}/results_{args.algorithm}_{args.version}_{args.scenario}.json"

    # Saving results
    save_to_json(results, result_path) 
    with open(f"{args.results}/alarms_{config_name}_{args.version}_{args.scenario}.json", 'w') as jsonfile:
        json.dump(performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
        
    # ---------------------------------------------------------------------------------------------------------#    
        
    # Extracting Systemcalls from False Alarms
    false_alarm_list = [alarm for alarm in performance.alarms.alarms if not alarm.correct]
    
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
        containerList.append(FalseAlertContainer(alarm, false_alarm_recording_list, window_length, ngram_length))
        counter += 1    
    
    pprint("Playing back false positive alarms:")
    false_alarm_results = process_map(construct_Syscalls, containerList, chunksize = 50)
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
    
    
    pprint("All Artifical Recordings:")
    pprint(all_recordings)

    # Das hier einfach auf set_revalidation_data(all_recordings) setzen um die Trainingsbeispiele bei den Validierungsdaten einzufügen. TODO´(Muss noch evaluiert werden). 
    dataloader.set_retraining_data(all_recordings)

    ##### New BBs ############
    # STIDE
    if args.algorithm == 'stide':
        thread_aware = True
        window_length = 1000
        ngram_length = 5
        embedding_size = 10
        
        intEmbedding = IntEmbedding()
        ngram = Ngram([intEmbedding], thread_aware, ngram_length)
        decision_engine = Stide(ngram, window_length)

    # MLP - Rebuilding whole IDS BBs.
    elif args.algorithm == 'mlp':
        
        settings_dict = {} # Enthält die Konfig-Infos
        if args.config == '0':
            
            ##################################### Config 0 ######################################### 
            
            # Settings
            ngram_length = 5
            w2v_vector_size = 5
            w2v_window_size = 10
            thread_aware = True
            hidden_size = 64
            hidden_layers = 3
            batch_size = 256
            w2v_epochs = 1000
            learning_rate = 0.003
            window_length = 10

            settings_dict['ngram_length'] = ngram_length
            settings_dict['w2v_vector_size'] = w2v_vector_size
            settings_dict['w2v_window_size'] = w2v_window_size
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['w2v_epochs'] = w2v_epochs
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length

            # Building Blocks
            inte = IntEmbedding()

            w2v = W2VEmbedding(word=inte,
                           vector_size=w2v_vector_size,
                           window_size=w2v_window_size,
                           epochs=w2v_epochs,
                           thread_aware=thread_aware)
            
            ohe = OneHotEncoding(inte)

            ngram = Ngram([w2v], thread_aware, ngram_length + 1) 

            select = Select(ngram, start = 0, end = (w2v_vector_size * ngram_length)) 

            mlp = MLP(select,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )
            
            decision_engine = StreamSum(mlp, thread_aware, window_length)
        
        ##################################### Config 1 ######################################### 
        elif args.config == '1':
            
            # Settings
            ngram_length = 3
            w2v_vector_size = 8
            w2v_window_size = 15
            thread_aware = True
            hidden_size = 32
            hidden_layers = 4
            batch_size = 256
            w2v_epochs = 1000
            learning_rate = 0.003
            window_length = 100       
            
            
            settings_dict['ngram_length'] = ngram_length
            settings_dict['w2v_vector_size'] = w2v_vector_size
            settings_dict['w2v_window_size'] = w2v_window_size
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['w2v_epochs'] = w2v_epochs
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length
            
            
            # Building Blocks

            inte = IntEmbedding()

            w2v = W2VEmbedding(word=inte,
                           vector_size=w2v_vector_size,
                           window_size=w2v_window_size,
                           epochs=w2v_epochs,
                           thread_aware=thread_aware)
            
            ohe = OneHotEncoding(inte)

            ngram = Ngram([w2v], thread_aware, ngram_length + 1) 

            select = Select(ngram, start = 0, end = (w2v_vector_size * ngram_length)) 

            mlp = MLP(select,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )
            
            decision_engine = StreamSum(mlp, thread_aware, window_length)
        
        ##################################### Config 2 ######################################### 
        elif args.config == '2':
            
            # Settings
            ngram_length = 7
            thread_aware = True
            hidden_size = 64
            hidden_layers = 3
            batch_size = 256
            learning_rate = 0.003
            window_length = 5

            
            settings_dict['ngram_length'] = ngram_length
            settings_dict['thread_aware'] = thread_aware
            settings_dict['hidden_size'] = hidden_size
            settings_dict['hidden_layers'] = hidden_layers
            settings_dict['batch_size'] = batch_size
            settings_dict['learning_rate'] = learning_rate
            settings_dict['window_length'] = window_length
            
            # Building Blocks
            inte = IntEmbedding()
            
            ohe = OneHotEncoding(inte)
            
            ngram_ohe = Ngram([ohe], thread_aware, ngram_length + 1)
            
            select_ohe = Select(ngram_ohe, 0, (ngram_length * 23)) # TODO: 23 works only for 2019:2017 rn
            
            mlp = MLP(select_ohe,
                ohe,
                hidden_size,
                hidden_layers,
                batch_size,
                learning_rate
            )   
    
            decision_engine = StreamSum(mlp, thread_aware, window_length)
            
        else:
            exit('Unknown configuration of MLP. Exiting.')
        
        
    # AE - TODO
    elif args.algorithm == 'ae':
        pass
    # SOM - TODO
    elif args.algorithm == 'som':
        pass


    ######## New IDS ########################
    ids_retrained = IDS(data_loader=dataloader,
        resulting_building_block=decision_engine,
        plot_switch=False,
        create_alarms=True)
        
    dataloader.unload_retraining_data() # Cleaning dataloader for performance issues
        
    pprint("At evaluation:")
    
    #ids_retrained.determine_threshold()  # Hier wird der Schwellenwert noch neu bestimmt.
    pprint(f"Freezing Threshold on: {ids.threshold}")
    ids_retrained.threshold = ids.threshold
    performance_new = ids.detect_parallel()        
    results_new = performance_new.get_results()
    pprint(results_new)

    # Preparing second results
    algorithm_name = f"{args.algorithm}_retrained"
    config_name = f"algorithm_{algorithm_name}_p_{args.play_back_count_alarms}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"

    # Enrich results with configuration 
    results_new['algorithm'] = algorithm_name
    results_new['play_back_count_alarms']= args.play_back_count_alarms
    
    for key in settings_dict.keys():
        results[key] = settings_dict[key]
    # results_new['ngram_length'] = ngram_length
    # results_new['window_length'] = window_length
    # results_new['thread_aware'] = thread_aware
    results_new['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results_new['scenario'] =  args.version + "/" + args.scenario
    result_new_path = f"{args.results}/results_{algorithm_name}_p_{args.play_back_count_alarms}_{args.version}_{args.scenario}.json"

    # Save results
    save_to_json(results_new, result_new_path) 
    with open(f"{args.results}/alarms_{config_name}_{args.version}_{args.scenario}.json", 'w') as jsonfile:
        json.dump(performance_new.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
   
   