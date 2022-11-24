from pprint import pprint
from datetime import datetime

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold

from algorithms.ids import IDS
from algorithms.persistance import save_to_mongo 
from algorithms.decision_engines.stide import Stide

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory



if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 5
    thread_aware = True
    window_length = 100

    # path = '/media/tk/SSD/ganzmann_data/'
    path='../../WHK/Data/real_world/'
    # data loader for scenario
    dataloader = dataloader_factory(path, direction=Direction.CLOSE)

    # embedding
    int_embedding = IntEmbedding()

    # extra parameter

    # ngrams
    ngram = Ngram(feature_list=[int_embedding],
                  thread_aware=thread_aware,
                  ngram_length=ngram_length)

    # decision engine (DE)
    de = Stide(ngram)

    stream_sum = StreamSum(
            de,
            thread_aware=False,
            window_length=window_length,
            wait_until_full=False)

    decider = MaxScoreThreshold(stream_sum)

    # define the used features
    ids = IDS(data_loader=dataloader,
              resulting_building_block=decider,
              plot_switch=False)

    # detection
    results = ids.detect_parallel().get_results()
    pprint(results)

    # enrich results with configuration and save to disk
    results['config'] = ids.get_config_tree_links()
    results['scenario'] = 'real_world' 
    results['direction'] = dataloader.get_direction_string()
    results['date'] = str(datetime.now().date())

    save_to_mongo(results)
