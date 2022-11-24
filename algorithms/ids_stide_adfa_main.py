import os
import sys

from pprint import pprint
from algorithms.ids import IDS
from algorithms.features.impl.ngram import Ngram
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.stream_sum import StreamSum
from dataloader.dataloader_factory import dataloader_factory
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from algorithms.persistance import save_to_mongo

if __name__ == '__main__':

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = os.environ['LID_DS_BASE']
        except KeyError:
            raise ValueError("No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE")

    kwargs = {'val_count': 20,  # size of validation data set (recordings)
              'attack': None,  # ADFA-LD Attack
              'val_train_add': 2000}  # number of validation recordings that will be added to training data

    dataset = 'ADFA-LD'
    dataloader = dataloader_factory(os.path.join(lid_ds_base_path, dataset), **kwargs)

    thread_aware = False
    window_length = 50
    ngram_length = 9

    ### building blocks    
    # first: map each systemcall to an integer
    int_embedding = IntEmbedding()
    # now build ngrams from these integers
    ngram = Ngram([int_embedding], thread_aware, ngram_length)
    # finally calculate the STIDE algorithm using these ngrams
    stide = Stide(ngram)
    stream_sum = StreamSum(stide, False, window_length, False)
    decider = MaxScoreThreshold(stream_sum)

    ### the IDS
    ids = IDS(data_loader=dataloader,
              resulting_building_block=decider,
              create_alarms=True,
              plot_switch=False)

    # detection
    # normal / seriell
    results = ids.detect_parallel().get_results()

    # parallel / map-reduce

    # to get alarms:
    # print(performance.alarms.alarm_list)

    ### print results
    pprint(results)

    save_to_mongo(results)
