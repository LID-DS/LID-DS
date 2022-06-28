from pprint import pprint
from copy import deepcopy
from tqdm.contrib.concurrent import process_map
from functools import reduce

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.ids import IDS
from algorithms.performance_measurement import Performance

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction


class Container:
        def __init__(self, ids, recording):
            self.ids = ids
            self. recording = recording

def calculate(struct: Container) -> Performance:
        # Copy the whole IDS with its building blocks
        working_copy = deepcopy(struct.ids)
        # Calculate the performance on the current recording
        performance = working_copy.detect_on_recording(struct.recording)
        return performance


if __name__ == '__main__':

    # todo: change this to your base path
    lid_ds_base_path = "/media/sf_Masterarbeit/Material"
    lid_ds_version = "LID-DS-2021"
    scenario_name = "CVE-2017-7529"
    scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH) # just load < closing system calls for this example

    ### features (for more information see Paper: "Improving Host-based Intrusion Detection Using Thread Information", International Symposium on Emerging Information Security and Applications (EISA), 2021)
    thread_aware = True
    window_length = 1000
    ngram_length = 5

    ### building blocks    
    # first: map each systemcall to an integer
    int_embedding = IntEmbedding()
    # now build ngrams from these integers
    ngram = Ngram([int_embedding], thread_aware, ngram_length)
    # finally calculate the STIDE algorithm using these ngrams
    stide = Stide(ngram, window_length)

    ### the IDS    
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=False,
            plot_switch=True)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    
    # load test-data
    data = dataloader.test_data()
    
    # pack the data together with the ids
    containered_recordings = [Container(ids, recording) for recording in data]

    # Calculate parallel for every recording
    performance_list = process_map(calculate, containered_recordings, chunksize = 2)
    
    # Unite all of the results to one whole
    final_performance =  reduce(Performance.add, performance_list)

    ### print results 
    results = final_performance.get_results()
    pprint(results)
