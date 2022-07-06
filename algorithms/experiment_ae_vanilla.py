import sys
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
    ngram_length = 7
    enc_size = 10
    ae_hidden_size = int(math.sqrt(ngram_length * enc_size))

    ### building blocks  
    name = SyscallName()
    inte = IntEmbedding(name)
    w2v = W2VEmbedding(word=inte,vector_size=enc_size,window_size=10,epochs=1000)
    ngram = Ngram(feature_list = [w2v],thread_aware = thread_aware,ngram_length = ngram_length)
    ae = AE(ngram,ae_hidden_size,batch_size=256,max_training_time=120,early_stopping_epochs=10000)
    stream_window = StreamSum(ae,True,600)

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

    pprint(results)
