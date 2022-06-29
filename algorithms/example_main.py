from pprint import pprint
from datetime import datetime

from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.ngram import Ngram
from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from algorithms.paralell_wrapper import parallel_detect

if __name__ == '__main__':

    # todo: change this to your base path
    lid_ds_base_path = "/home/tk-whk/Documents/WHK/Data/"
    lid_ds_version = "LID-DS_2019"
    scenario_name = "CVE-2017-7529"
    scenario_path = f"{lid_ds_base_path}/{lid_ds_version}/{scenario_name}"        
    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE) # just load < closing system calls for this example

    ### features (for more information see Paper: "Improving Host-based Intrusion Detection Using Thread Information", International Symposium on Emerging Information Security and Applications (EISA), 2021)
    thread_aware = False
    window_length = 100
    ngram_length = 3

    ### building blocks    
    # first: map each systemcall to an integer
    int_embedding = IntEmbedding()
    # now build ngrams from these integers
    ngram = Ngram([int_embedding], thread_aware, ngram_length)
    # finally calculate the STIDE algorithm using these ngrams
    stide = Stide(ngram)
    
    ### the IDS    
    ids = IDS(data_loader=dataloader,
            resulting_building_block=stide,
            create_alarms=False,
            plot_switch=False)

    print("at evaluation:")
    # threshold
    ids.determine_threshold()
    # detection
    # ids.do_detection()
    performance = parallel_detect(recordings=dataloader.test_data(),
                                  ids=ids)


    ### print results and plot the anomaly scores
    results = performance.get_results()
    pprint(results)
    now = datetime.now()  # datetime object containing current date and time    
    dt_string = now.strftime("%Y-%m-%d_%H-%M-%S")  # YY-mm-dd_H-M-S    
    ids.draw_plot(f"results/figure_{dt_string}.png")
