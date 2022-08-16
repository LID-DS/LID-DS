import sys
import math
from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.decision_engines.mlp import MLP
from algorithms.decision_engines.som import Som
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.select import Select
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.one_hot_encoding import OneHotEncoding

from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':

    # getting the LID-DS base path, version and scenario from argument
    try:        
        lid_ds_base_path = sys.argv[1]
        lid_ds_version = sys.argv[2]
        scenario_name = sys.argv[3]
    except:
        print(f"Error, call with:\n> python3 {sys.argv[0]} lid_ds_base_path lid_ds_version scenario_name")
        exit()        

    scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

    ### features
    thread_aware = True
    ngram_length = 5
    enc_size = 5
    
    ## blocks
    name = SyscallName()
    inte = IntEmbedding(name)    
    w2v = W2VEmbedding(word=inte,vector_size=enc_size,window_size=20,epochs=5000)

    ngram = Ngram(
        feature_list = [w2v],
        thread_aware = thread_aware,
        ngram_length = ngram_length)

    som = Som(epochs=1000,input_vector=ngram,max_training_time=20)

    window = StreamSum(feature=som,thread_aware=True,window_length=10)

    ### the IDS    
    ids = IDS(data_loader=dataloader,
            resulting_building_block=window,
            create_alarms=False,
            plot_switch=False)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    results = ids.detect_parallel().get_results()

    #print(ae._cached_results.cache_info())

    pprint(results)

    #ids.draw_plot()
