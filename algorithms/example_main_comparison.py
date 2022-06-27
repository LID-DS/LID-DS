from calendar import c
import json
from pprint import pprint
from datetime import datetime

import os
from time import sleep

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
from algorithms.performance_measurement import Performance
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from algorithms.persistance import save_to_json
from copy import deepcopy
from tqdm.contrib.concurrent import process_map
from functools import reduce

# Take the entrypoint etc. from the existing example_main.py
if __name__ == '__main__':

    select_lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019", 
        "LID-DS-2021"
    ]

    # scenarios orderd by training data size asc
    # 0 - 14    
    select_scenario_number = 0
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

    # base path
    lid_ds_base_path = "/media/sf_Masterarbeit/Material"

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version[select_lid_ds_version_number]}/{scenario_names[select_scenario_number]}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # Results differ, currently BOTH was the best performing

    # A lot of features
    ###################
    thread_aware = True
    window_length = 1000
    ngram_length = 5
    embedding_size = 10
    #--------------------
    
    intEmbedding = IntEmbedding()
    ngram_1 = Ngram([intEmbedding], thread_aware, ngram_length)
    stide = Stide(ngram_1)

    ###################
    # the IDS
    generate_and_write_alarms = True
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)
    
    # Bestimme Schwellenwert
    ids.determine_threshold()

    # Lade Test-Datem
    data = dataloader.test_data()
    
    class Container:
        def __init__(self, ids, recording):
            self.ids = ids
            self. recording = recording


    containered_recordings = [Container(ids, recording) for recording in data]

    def calculate(struct: Container) -> Performance:
        # Copy the whole IDS with its building blocks
        working_copy = deepcopy(struct.ids)
        # Calculate the performance on the current recording
        performance = working_copy.detect_on_recording(struct.recording)
        return performance

    results = process_map(calculate, containered_recordings, chunksize = 1)


    completeResult = reduce(Performance.add, results) # Um die CFP zu bestimmen müsste ich wahrscheinlich noch einen Index mitgeben für jedes Recording. Dann nach dem Prozess-Map danach sortieren und dann die CFP usw. errechnen (TODO). Sind aber für mich unwichtig.

    results = completeResult.get_results()
    pprint(results)
    
    #pprint("Integer-Embedding:")
    #pprint(intEmbedding._syscall_dict)

    print("At evaluation:")
    # threshold
    #ids.determine_threshold()
    # detection
    #ids.do_detection()
    # print results
    
    #results = ids.performance.get_performance()
    #pprint(results)

    # Preparing results
    algorithm_name = "stide"
    config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"
    
    # Enrich results with configuration and save to disk
    results['algorithm'] = algorithm_name
    results['ngram_length'] = ngram_length
    results['window_length'] = window_length
    results['thread_aware'] = thread_aware
    results['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    
    result_path = f"results/results_{algorithm_name}_{lid_ds_version[select_lid_ds_version_number]}.json"

    
    #save_to_json(results, result_path) 

    # Generate alarms - care, the save_to_json takes care that the results-folder was created.
    #if generate_and_write_alarms:
    #    with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
    #        json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
    
    # -----------------        This will be my personal space right here        ------------------------------- 
    false_alarm_list = [alarm for alarm in ids.performance.alarms.alarms if not alarm.correct]
    
    # An diesem Punkt sind sämtliche false-Alarms in der false-alarm-list.

    # Dies hier ist notwenig um die richtigen Recordings in einer Liste zu erhalten, welche zu den False-Alarms gehören.
    basename_recording_list = set([os.path.basename(false_alarm.filepath) for false_alarm in false_alarm_list])
    false_alarm_recording_list = [recording for recording in dataloader.test_data() if os.path.basename(recording.path) in basename_recording_list]
    
    # Die neue Datenstruktur
    data_structure = {}
    for counter in range(len(false_alarm_list)):
        
        current_false_alarm = false_alarm_list[counter]
        faster_current_basename = os.path.basename(current_false_alarm.filepath)
    
        # Sucht anhand des Alarms das passende Recording dazu.
        for recording in false_alarm_recording_list:
            if os.path.basename(recording.path) == faster_current_basename:
                current_recording = recording
                
        # Funktioniert bis hier.
        #pprint(f"Current false alarm path: {os.path.basename(current_false_alarm.filepath)}")
        #pprint(f"Current recording path: {os.path.basename(current_recording.path)}")
        #pprint(current_false_alarm.filepath)
        
        ################ Optimieren ####################
        #systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= current_false_alarm.first_line_id and systemcall.line_id <= current_false_alarm.last_line_id]
        systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([current_false_alarm.first_line_id - window_length, 0]) and systemcall.line_id <= current_false_alarm.last_line_id] # mit Fensterbetrachtung
        
        # Hier muss noch kalkuliert werden, wie weit ich tatsächlich in der Datei nach vorne muss um alle originalen N-Grams herstellen zu können.
        
        if thread_aware:
            
            backwards_counter = max([current_false_alarm.first_line_id - window_length, 0])
            if backwards_counter != 0:
                thread_id_set = set([systemcall.thread_id() for systemcall in systemcall_list])
                pprint("Threads:")
                pprint(thread_id_set)
    
                # Init    
                dict = {}
                for thread in thread_id_set:
                    dict[thread] = 0
    
                # Jetzt muss ich theoretisch rückwärts das Teil runter gehen. 
                # Diese Funktion checkt darauf, ob alle Einträge von dict mindestens max sind und gibt nur dann True zurück
                def enough_calls(dict, max): 
                    for key in dict.keys():
                        if dict[key] < max:
                            return False
                    return True    

                # Die Idee ist die folgende: Gehe solange zurück, bis du n Systemcalls für jede thread_id hast. Das garantiert uns die richtigen N-Grams, da diese Systemcalls das N-Gram entsprechend auffüllen, bevor wir bei first_line - window ankommen.
                # Dabei nimmst du den momentanen call und checkst, ob er mit unseren Threads zu tun hat. Da uns die NGrams der anderen Threads nicht interessieren, werfen wir die zugehörigen Systemcalls einfach weg
                pprint(f"Starting on line {backwards_counter}:")
            
                # Mach mir den Generator zur Liste. Hier könnte ich ab der last_line_id auch schon abbrechen für Performance.
                temp_list = []
                for x in current_recording.syscalls():
                    temp_list.append(x)
                #pprint(temp_list)
            
            
                expected_count_calls = (current_false_alarm.last_line_id - current_false_alarm.first_line_id) + 1 + window_length + len(dict) * ngram_length
                pprint(f"Expected number of systemcalls: {expected_count_calls}")
            
                while(not enough_calls(dict, ngram_length) and backwards_counter != 0):
                    current_call = temp_list[backwards_counter]
                    #pprint(current_call)
                    if current_call.thread_id() in dict.keys() and dict[current_call.thread_id()] <= ngram_length: ################# BAUSTELLE #######################
                        dict[current_call.thread_id()] += 1 
                        systemcall_list.insert(0, current_call)
                    backwards_counter -= 1
                print(f"Ended with backwards_counter: {backwards_counter} and final dict{dict}")
        else:
            # Hier muss ich auch die N-Gram length noch abziehen um das N-Gram zu initialisieren.
            systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([current_false_alarm.first_line_id - window_length - ngram_length, 0]) and systemcall.line_id <= current_false_alarm.last_line_id] # mit Fensterbetrachtung
        #pprint("Extracted calls:")
        #pprint(f"First line id: {current_false_alarm.first_line_id} Last line id: {current_false_alarm.last_line_id}")
        #for call in systemcall_list:
            #pprint(f"{call}, Embedding: {intEmbedding._syscall_dict[call.name()]}")
        
        # Rein damit in was persistentes. ID hinzugefügt um verschiedene Alerts in der gleichen ZIP zu unterscheiden.
        data_structure[os.path.basename(current_false_alarm.filepath) + "_" + '{:0>5}'.format(counter)] = systemcall_list
        
    
    #pprint(data_structure)
    
        
    # Jetzt muss ich aus den Recordings die Systemcalls sammeln und auf die beschränken, welche innerhalb der Lines des False-Alarm sind.
    # Hier muss ich auch die Window-Größe betrachten und von der StartNummer noch abziehen. 
    # Um von 0 wegzukommen kann ich sowas wie Max(x-100, 0) machen.
    # Einen check-Recording muss ich nicht ausführen, da das schon in der INIT des Recordings passiert.
    # Perfekt, es werden genau die Systemcalls extrahiert, die in den Grenzen der Werte im Alarm-Objekt liegen, sogar in der richtigen Reihenfolge. 
    # Als nächstes nehme ich noch das Fenster davor hinzu. Klappt auch wunderbar. Dann fehlt noch die Datenstruktur, die das ganze zusammenführt und verwendbar macht. 
    # Die hat erstmal den vorläufigen Namen "data_structure". Im nächsten Schritt muss ich nun das IDS nochmal mit den neuen Systemcalls weitertrainieren.
    
    # Man kännte noch überlegen die ID von hinten nach vorne zu verschieben. Ist bisher aber nicht so wichtig.
    



    # Note: Das IDS hat keine Trainingsmethode, sondern nur Threshold und Detection-Methoden. Eine Möglichkeit wäre, einfach die neuen Trainingsdaten zu den alten hinzuzufügen und dann ein neues IDS damit zu erstellen. Dazu muss ich an den DataLoader und dessen
    # Methode training_data() rankommen. Ich könnte dann einfach neue Recordings pro False-Alarm bauen. Dann muss ich diese in einer Liste verpacken und dem DataLoader mittels add_retraining_data(data) übergeben.
   
    
    # TODO?: Taktik Nummer zwei bedeutet, die neuen Daten zum schon trainierten Satz hinzuzufügen. Das wird sich wohl als schwieriger gestalten.
    
    
    # Also bastel ich mir zuerst ein künstliches Recording zusammen, das nur für Trainingsdaten geeignet ist (auf Wish bestellt)
    class ArtificialRecording:
        def __init__(self, name, syscalls):
            self.name = name
            self._syscalls = syscalls
            
        def syscalls(self) -> list:
            return self._syscalls
        
        def __repr__(self) -> str:
            return f"ArtificialRecording, Name: {self.name}, Nr. of Systemcalls: {len(self._syscalls)}"
        
    # MODYFIABLE! Hier kann ich auch einstellen, nur einen Teil der False-Alarms ins Trainig zurückgehen zu lassen.
    all_recordings = []
    # Iteriere durch alle False-Alarms und nutze die jeweiligen SystemCalls. 
    for key in data_structure.keys():
        new_recording = ArtificialRecording(key, data_structure[key])
        all_recordings.append(new_recording)

    pprint("All Artifical Recordings:")
    pprint(all_recordings)

    # Jetzt verändere ich den DataLoader:
    dataloader.set_retraining_data(all_recordings)
    
    # Und generiere das IDS nochmal völlig neu.
    ids_retrained = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)

    pprint("At evaluation:")
    # threshold
    #ids_retrained.determine_threshold()
    pprint(f"Freezing Threshold on: {ids.threshold}")
    ids_retrained.performance.set_threshold(ids.threshold)
    
    # detection
    ids_retrained.do_detection()
    # print results
    results_new = ids_retrained.performance.get_performance()
    pprint(results_new)
    
      # Preparing results
    algorithm_name = "stide_retrained"
    config_name = f"algorithm_{algorithm_name}_n_{ngram_length}_w_{window_length}_t_{thread_aware}"
    
    # Enrich results with configuration and save to disk
    results_new['algorithm'] = algorithm_name
    results_new['ngram_length'] = ngram_length
    results_new['window_length'] = window_length
    results_new['thread_aware'] = thread_aware
    results_new['config'] = ids.get_config() # Produces strangely formatted Config-Print
    results_new['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    
    result_new_path = f"results/results_{algorithm_name}_{lid_ds_version[select_lid_ds_version_number]}.json"
    
    save_to_json(results_new, result_new_path) 

    # Generate alarms - care, the save_to_json takes care that the results-folder was created.
    if generate_and_write_alarms:
        with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
            json.dump(ids_retrained.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)
    
    
    
    
    
    
    
    
    
    
    
    
    
    