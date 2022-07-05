from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.int_embedding import IntEmbedding

from algorithms.ids import IDS
from algorithms.persistance import save_to_json
from algorithms.decision_engines.stide import Stide

from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory

from pprint import pprint


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
    de = Stide(ngram,
               window_length=window_length)

    # define the used features
    ids = IDS(data_loader=dataloader,
              resulting_building_block=de,
              plot_switch=False)

    # threshold
    ids.determine_threshold()
    # detection
    results = ids.detect().get_performance()
    pprint(results)

    # enrich results with configuration and save to disk
    results['algorithm'] = "STIDE"
    results['ngram_length'] = ngram_length
    results['window_length'] = window_length
    results['thread_aware'] = thread_aware
    results['scenario'] = 'real_world'
    result_path = 'results/results_real_world.json'

    save_to_json(result_dict=results, path=result_path)
