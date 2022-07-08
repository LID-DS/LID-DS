import json
from pprint import pprint

import os
from time import time

from algorithms.decision_engines.ae import AE, AEMode
from algorithms.decision_engines.som import Som
from algorithms.decision_engines.stide import Stide
from algorithms.decision_engines.mlp import MLP
from algorithms.features.impl.stream_sum import StreamSum
#from algorithms.features.impl.Sum import Sum
#from algorithms.features.impl.Difference import Difference
#from algorithms.features.impl.Minimum import Minimum
#from algorithms.features.impl.PositionInFile import PositionInFile
#from algorithms.features.impl.PositionalEncoding import PositionalEncoding
from algorithms.features.impl.select import Select
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.syscall_name import SyscallName

from algorithms.ids import IDS
from algorithms.performance_measurement import Performance
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.persistance import save_to_json
from copy import deepcopy
from tqdm.contrib.concurrent import process_map
from functools import reduce



def enough_calls(dict, max): 
    for key in dict.keys():
        if dict[key] < max:
            return False
    return True       
    
    
class FalseAlertContainer:
    def __init__(self, alarm, alarm_recording_list, ngram_length, thread_aware, window_length = 0) -> None:
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


class Container:
        def __init__(self, ids, recording):
            self.ids = ids
            self. recording = recording
            
class ArtificialRecording:
    def __init__(self, name, syscalls):
        self.name = name
        self._syscalls = syscalls
            
    def syscalls(self) -> list:
        return self._syscalls
        
    def __repr__(self) -> str:
        return f"ArtificialRecording, Name: {self.name}, Nr. of Systemcalls: {len(self._syscalls)}"
        
        
def calculate(struct: Container) -> Performance:
    #pprint("Moin")
    #sleep(1)
    
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
    
    if container.window_length is None:
        container.window_length = 0
    
    systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([alarm.first_line_id - container.window_length, 0]) and systemcall.line_id <= alarm.last_line_id] # mit Fensterbetrachtung
    
    
    if container.thread_aware:
            
        backwards_counter = max([alarm.first_line_id - container.window_length -1, 0]) # -1 weil ich nicht den ersten Call des Windows will, den habe ich ja schon durch die systemcall List
        if backwards_counter != 0:
            thread_id_set = set([systemcall.thread_id() for systemcall in systemcall_list])
            #pprint("Threads:")
            #print(thread_id_set)
    
            # Init    
            dict = {}
            for thread in thread_id_set:
                dict[thread] = 0
    
            # Jetzt muss ich theoretisch rückwärts das Teil runter gehen. 
            # Diese Funktion checkt darauf, ob alle Einträge von dict mindestens max sind und gibt nur dann True zurück


            # Die Idee ist die folgende: Gehe solange zurück, bis du n Systemcalls für jede thread_id hast. Das garantiert uns die richtigen N-Grams, da diese Systemcalls das N-Gram entsprechend auffüllen, bevor wir bei first_line - window ankommen.
            # Dabei nimmst du den momentanen call und checkst, ob er mit unseren Threads zu tun hat. Da uns die NGrams der anderen Threads nicht interessieren, werfen wir die zugehörigen Systemcalls einfach weg
            #pprint(f"Starting on line {backwards_counter}:")
            
            # Mach mir den Generator zur Liste. Hier könnte ich ab der last_line_id auch schon abbrechen für Performance.
            temp_list = []
            for x in current_recording.syscalls():
                temp_list.append(x)
                if x.line_id == alarm.last_line_id:
                    break # Geh raus sobald du genug Systemcalls für diesen Alarm hast
            #pprint(f"Count of Systemcalls in this recording: {len(temp_list)}")
            
            # Das macht es der Bestimmung der Line_id wesentlich leichter, da von hinten (current_false_alarm.last_line_id ) nach vorne gegangen wird und nicht von Anfang an durch die gesamte Datei.
            # Da wir nicht über Indizes arbeiten sondern über die lineID, geht es klar das der backwards_counter weiter verringert wird.
            temp_list.reverse() 
            
            #expected_count_calls = (alarm.last_line_id - alarm.first_line_id) + 1 + container.window_length + len(dict) * container.ngram_length # +1 um den End-Call auch mitzunehmen
            #pprint(f"Expected number of systemcalls: {expected_count_calls}")
                
            while(not enough_calls(dict, container.ngram_length) and backwards_counter != 0):
                current_call = None
                for call in temp_list: # Leider muss ich den richtigen Call anhand der line_id suchen, da ich mich nicht auf deren Kontinuität verlassen kann.
                    if call.line_id == backwards_counter:
                        current_call = call  
                        break  
                    
                # Es gibt anscheinend Line_IDs, die nicht in der Liste von Systemcalls einem der Calls entsprechen.
                if current_call is None:
                    backwards_counter -=1 
                    continue
                    
                #pprint(current_call)
                if current_call.thread_id() in dict.keys() and dict[current_call.thread_id()] < container.ngram_length: ################# BAUSTELLE ####################### - ginge theoretisch auch n-gram-length -1 ? Theoretisch wäre dann ja trotzdem das richtige n-gram initialisiert oder?
                    dict[current_call.thread_id()] += 1 
                    systemcall_list.insert(0, current_call)
                        
                backwards_counter -= 1
            #print(f"Ended with backwards_counter: {backwards_counter} and final dict{dict}")
            #pprint(f"Acutal number of systemcalls: {len(systemcall_list)}")
    else:
        # Ohne Beachtung der ThreadIDs
        systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([alarm.first_line_id - container.window_length - container.ngram_length, 0]) and systemcall.line_id <= alarm.last_line_id] # mit Fensterbetrachtung
        
        
    result = FalseAlertResult(f"{os.path.basename(current_recording.path)}_{str(round(time()*1000))[-5:]}", systemcall_list)
    #pprint(f"NEW NAME OF RECORDING: {os.path.basename(current_recording.path)}_{str(round(time()*1000))[-5:]}")
    result.structure[result.name] = result.syscalls
        
    return result    
    
    
    
    
# Take the entrypoint etc. from the existing example_main.py
if __name__ == '__main__':

    select_lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]

    # scenarios orderd by training data size asc
    # 0 - 14    
    select_scenario_number = 1
    scenario_names = [
        "CVE-2017-7529",
        "CVE-2014-0160",
        "CVE-2012-2122",
        "Bruteforce_CWE-307",
        "CVE-2020-23839",
        "CWE-89-SQL-injection", # LID-DS-2021 exclusive
        "SQL_Injection_CWE-89", # LID-DS-2019 exclusive
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

    # base path
    lid_ds_base_path = "/media/sf_Masterarbeit/Material"
    # lid_ds_base_path = "S:\Masterarbeit\Material"
    play_back_count_alarms = 'all'


    scenario_path = f"{lid_ds_base_path}/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # Results differ, currently BOTH was the best performing

    # A lot of features
    ###################
    #thread_aware = True
    #window_length = 1000
    #ngram_length = 5
    #embedding_size = 10
    #--------------------
    
    #intEmbedding = IntEmbedding()
    #ngram_1 = Ngram([intEmbedding], thread_aware, ngram_length)
    
    # w2v = W2VEmbedding(embedding_size,10,1000,scenario_path,"Models/W2V/",True)
    # ohe = OneHotEncoding(input=intEmbedding)
    
    # ngram_2 = Ngram([w2v],True,ngram_length)
    # ngram_3 = Ngram([ohe], True, ngram_length)

    ####################################### STIDE - Specs ###################################
    # thread_aware = True
    # window_length = 1000
    # ngram_length = 5
        
    # intEmbedding = IntEmbedding()
    # ngram_1 = Ngram([intEmbedding], thread_aware, ngram_length)
    # decision_engine = Stide(ngram_1, window_length=window_length)
    ####################################### STIDE - Specs - End #############################

    # pe = PathEvilness(scenario_path, force_retrain=True)

    # rv = ReturnValue()

    # concat = Concat([rv])
    # som = Som(concat)

    ####################################### MLP - Specs ##################################
    ngram_length = 7
    w2v_vector_size = 8
    w2v_window_size = 10
    thread_aware = True
    hidden_size = 64
    hidden_layers = 3
    batch_size = 256
    epochs = 1000
    learning_rate = 0.003
        
    syscall = SyscallName()
    inte = IntEmbedding(syscall)
        
    w2v = W2VEmbedding(word=inte,
                       vector_size=w2v_vector_size,
                       window_size=w2v_window_size,
                       epochs=epochs,
                       thread_aware=thread_aware)
    
    # Soll künstlich ein Ngram der Größe NGram-Length+1 erzeugen, damit wir NGram-Length viele Inputs haben und das Letzte als Output haben.
    # Das OHE nimmt ja immer den aktuellen Call und dadurch ist der aktuelle Call das Label, während Select nur die vorigen N-Gram-Length viele Systemcalls reingibt. 
    ngram = Ngram([w2v], thread_aware, ngram_length + 1) 
    select = Select(ngram, 0, (ngram_length * w2v_vector_size)) 

    ohe = OneHotEncoding(inte)
        
    mlp = MLP(select,
        ohe,
        hidden_size,
        hidden_layers,
        batch_size,
        learning_rate
    )   
    
    stream = StreamSum(mlp, thread_aware, window_length=100)
        
    decision_engine = stream
    ####################################### MLP - Specs - End ##############################



    ######################################## AE - Specs ####################################
    # ngram_length = 7
    # w2v_size = 5
    # w2v_window_size = 10
    # thread_aware = True
    # hidden_size = int(math.sqrt(ngram_length * w2v_size))
    # epochs = 500
    # batch_size = 512
    
    
    # syscall = SyscallName()
    # w2v = W2VEmbedding(syscall,
    #                    vector_size= w2v_size, 
    #                    window_size= w2v_window_size,
    #                    epochs= epochs
    #                     )
    
    # ngram_2 = Ngram([w2v], thread_aware, ngram_length)
    # decision_engine = AE(ngram_2,
    #         hidden_size,
    #         AEMode.LOSS,
    #         batch_size
    #         )
    ######################################## AE - Specs - End ###############################


    ######################################## SOM - Specs ####################################
    # ngram_length = 7
    # w2v_size = 5
    # som_epochs = 1000
    # som_size = 20
    # thread_aware = True
    # epochs = 50
    # window_length=10

    # w2v = W2VEmbedding(SyscallName(),
    #                    vector_size= w2v_size, 
    #                    window_size= w2v_size,
    #                    epochs= epochs
    #                 )
    
    # ngram = Ngram([w2v], thread_aware, ngram_length)
    
    # ohe = OneHotEncoding(input=ngram)

    # decision_engine = Som(input_vector=ngram,
    #           epochs=som_epochs,
    #           size=som_size)
    ######################################## SOM - Specs - End ###############################


    ###################
    # the IDS


    generate_and_write_alarms = True
    ids = IDS(data_loader=dataloader,
            resulting_building_block=decision_engine,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)
    
    # Bestimme Schwellenwert
    ids.determine_threshold()
    
    #ids.detect()
    performance = ids.detect()
    results = performance.get_results()
    pprint(results)

    pprint(mlp._result_dict.values())

    #print("At evaluation:")
    # Preparing results
    algorithm_name = "mlp"
    config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_t_{thread_aware}"
    
    # Enrich results with configuration and save to disk
    results['algorithm'] = algorithm_name
    results['ngram_length'] = ngram_length
    results['thread_aware'] = thread_aware
    results['hidden_size'] = hidden_size
    results['hidden_layers'] = hidden_layers
    results['batch_size'] = batch_size
    results['epochs'] = epochs
    results['learning_rate'] = learning_rate
    results['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    
    result_path = f"results/results_{algorithm_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json"
    
    save_to_json(results, result_path) 

    # Generate alarms - care, the save_to_json takes care that the results-folder was created.
    with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
        json.dump(performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
    
    # -----------------        This will be my personal space right here        ------------------------------- 
    false_alarm_list = [alarm for alarm in performance.alarms.alarms if not alarm.correct]
    #pprint(false_alarm_list)
    if not false_alarm_list:
        exit('Didn\'t found any false positives! Interrupting.')
    

    # An diesem Punkt sind sämtliche false-Alarms in der false-alarm-list.
    # Dies hier ist notwenig um die richtigen Recordings in einer Liste zu erhalten, welche zu den False-Alarms gehören.
    basename_recording_list = set([os.path.basename(false_alarm.filepath) for false_alarm in false_alarm_list])
    false_alarm_recording_list = [recording for recording in dataloader.test_data() if os.path.basename(recording.path) in basename_recording_list]
    

    containerList = []
    for alarm in false_alarm_list: 
        containerList.append(FalseAlertContainer(alarm, false_alarm_recording_list, ngram_length, thread_aware))
    
    start = time()
    pprint("Playing back false positive alarms:")
    alarm_results = process_map(construct_Syscalls, containerList, chunksize = 1, max_workers = 5)
    
    #pprint(alarm_results)
    
    final_results = reduce(FalseAlertResult.add, alarm_results)
    #pprint(final_results)
    end = time() 
    pprint(f"Parallel took {end-start} seconds.")
    
 
    # MODYFIABLE! Hier kann ich auch einstellen, nur einen Teil der False-Alarms ins Training zurückgehen zu lassen.
    all_recordings = []
    #pprint(f"Number of played back Alarms: {limit} / {len(data_structure)}")
    counter = 0
    pprint("Using parallel played back:")
    # Iteriere durch alle False-Alarms und nutze die jeweiligen SystemCalls. 
    for key in final_results.structure.keys():
        if play_back_count_alarms != 'all' and counter == int(play_back_count_alarms):
            break
        new_recording = ArtificialRecording(key, final_results.structure[key])
        all_recordings.append(new_recording)
        counter += 1
    
    if not all_recordings:
        exit(f'{play_back_count_alarms} played back alarms led to playing back zero false alarms. Program stops.')
    
    
    #pprint("All Artifical Recordings:")
    #pprint(all_recordings)


    # Jetzt verändere ich den DataLoader:
    dataloader.set_retraining_data(all_recordings)
    #dataloader.set_revalidation_data(all_recordings)
    
    # Und generiere das IDS nochmal völlig neu.
    #intEmbedding = IntEmbedding()
    #ngram = Ngram([intEmbedding], thread_aware, ngram_length)
    #stide = Stide(ngram, window_length=window_length)
    
    
    ids_retrained = IDS(data_loader=dataloader,
            resulting_building_block=decision_engine,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)

    # Cleaning dataloader for performance issues. Deepcopy is probably the thing which slows down the whole execution.
    dataloader.unload_retraining_data()
    #pprint("At evaluation:")
    # threshold
    #ids_retrained.determine_threshold()
    pprint(f"Freezing Threshold on: {ids.threshold}")
    ids_retrained.threshold = ids.threshold 
    
    # Get the results together again
    performance_new = ids_retrained.detect()

    # Print the results
    results_new = performance_new.get_results()
    pprint(results_new)

    # Preparing results
    algorithm_name = "stide_retrained"
    config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_t_{thread_aware}"
    
    # Enrich results with configuration and save to disk
    results_new['algorithm'] = algorithm_name
    results_new['ngram_length'] = ngram_length
    results_new['thread_aware'] = thread_aware
    results_new['hidden_size'] = hidden_size
    results_new['hidden_layers'] = hidden_layers
    results_new['batch_size'] = batch_size
    results_new['epochs'] = epochs
    results_new['learning_rate'] = learning_rate
    results_new['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results_new['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    
    result_new_path = f"results/results_{algorithm_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json"
    
    save_to_json(results_new, result_new_path) 

    # Generate alarms - care, the save_to_json takes care that the results-folder was created.
    if generate_and_write_alarms:
        with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
            json.dump(performance_new.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
    
    
    
    
    
    
    
    
    
    
    
    
    
    