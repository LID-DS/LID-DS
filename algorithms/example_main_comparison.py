import json
from pprint import pprint
from datetime import datetime

import os

from pandas import concat
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
    window_length = 100
    ngram_length = 7
    embedding_size = 10
    #--------------------
    
    intEmbedding = IntEmbedding()
    ngram_1 = Ngram([intEmbedding],True,ngram_length)
    
    # w2v = W2VEmbedding(embedding_size,10,1000,scenario_path,"Models/W2V/",True)
    # ohe = OneHotEncoding(input=intEmbedding)
    
    # ngram_2 = Ngram([w2v],True,ngram_length)
    # ngram_3 = Ngram([ohe], True, ngram_length)
    
    stide = Stide(ngram_1)

    # ae = AE(ngram_2, 5, AEMode.LOSS, batch_size=512)

    # pe = PathEvilness(scenario_path, force_retrain=True)

    # rv = ReturnValue()

    # concat = Concat([rv])
    # som = Som(concat)




    ###################
    # the IDS
    generate_and_write_alarms = True
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=generate_and_write_alarms,
            plot_switch=False)

    print("At evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
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
    results['scenario'] =  lid_ds_version[select_lid_ds_version_number] + "/" + scenario_names[select_scenario_number]
    
    result_path = f"results/results_{algorithm_name}_{lid_ds_version[select_lid_ds_version_number]}.json"
    #pprint(os.getcwd())
    #pprint(os.path.basename(os.getcwd()))
    #pprint(os.path.dirname(os.getcwd()))
    
    save_to_json(results, result_path) 

    # Generate alarms - care, the save_to_json takes care that the results-folder was created.
    if generate_and_write_alarms:
        with open(f"results/alarms_{config_name}_{lid_ds_version[select_lid_ds_version_number]}_{scenario_names[select_scenario_number]}.json", 'w') as jsonfile:
            json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str, indent=2)

    # plot
    # now = datetime.now()  # datetime object containing current date and time    
    # dt_string = now.strftime("%Y-%m-%d_%H-%M-%S")  # YY-mm-dd_H-M-S    
    # ids.draw_plot(f"results/figure_{config_name}_{dt_string}.png")
    
    # -----------------        This will be my personal space right here        ------------------------------- 
    false_alarm_list = [alarm for alarm in ids.performance.alarms.alarms if not alarm.correct]
    
    # An diesem Punkt sind sämtliche false-Alarms in der false-alarm-list.

    # Dies hier ist notwenig um die richtigen Recordings in einer Liste zu erhalten, welche zu den False-Alarms gehören.
    basename_recording_list = [os.path.basename(x.filepath) for x in false_alarm_list]
    false_alarm_recording_list = [x for x in dataloader.test_data() if os.path.basename(x.path) in basename_recording_list]

    pprint("Vergleiche die Listen auf gleiche Reihenfolge:")
    for x in false_alarm_list:
        pprint(x.filepath)
    pprint("Zweite:")
    for x in false_alarm_recording_list:
        pprint(x.name)

    # Bisher sieht es so aus, als ob immer die gleiche Reihenfolge der Dateien eingehalten wird. Dadurch kann ich nun einen Counter, der auf die Indexe zugreift nutzen.

    pprint("Resulting list of recordings which have to be handled:")
    
    # Die neue Datenstruktur
    data_structure = {}
    for _ in range(len(false_alarm_list)):
        current_recording = false_alarm_recording_list.pop(0)
        current_false_alarm = false_alarm_list.pop(0)
        
        # Works as intended.
        pprint(f"Current recording: {current_recording.name}")
        #pprint(current_false_alarm.filepath)
        
        systemcall_list = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= current_false_alarm.first_line_id and systemcall.line_id <= current_false_alarm.last_line_id]
        # systemcall_list_with_window = [systemcall for systemcall in current_recording.syscalls() if systemcall.line_id >= max([current_false_alarm.first_line_id - window_length, 0]) and systemcall.line_id <= current_false_alarm.last_line_id]

        pprint("Extracted calls:")
        pprint(len(systemcall_list))
        #for call in systemcall_list:
        #    pprint(call.name())
        
        # Rein damit in was persistentes.
        data_structure[os.path.basename(current_false_alarm.filepath)] = systemcall_list
        
    pprint(data_structure)
        
        
    # Jetzt muss ich aus den Recordings die Systemcalls sammeln und auf die beschränken, welche innerhalb der Lines des False-Alarm sind.
    # Hier muss ich auch die Window-Größe betrachten und von der StartNummer noch abziehen. 
    # Um von 0 wegzukommen kann ich sowas wie Max(x-100, 0) machen.
    # Einen check-Recording muss ich nicht ausführen, da das schon in der INIT des Recordings passiert.
    # Perfekt, es werden genau die Systemcalls extrahiert, die in den Grenzen der Werte im Alarm-Objekt liegen, sogar in der richtigen Reihenfolge. 
    # Als nächstes nehme ich noch das Fenster davor hinzu. Klappt auch wunderbar. Dann fehlt noch die Datenstruktur, die das ganze zusammenführt und verwendbar macht. 
    # Die hat erstmal den vorläufigen Namen "data_structure". Im nächsten Schritt muss ich nun das IDS nochmal mit den neuen Systemcalls weitertrainieren.
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    