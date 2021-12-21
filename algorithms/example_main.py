from pprint import pprint

from torch.utils import data

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.average import Average
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

from algorithms.persistance import save_to_json, load_from_json

if __name__ == '__main__':
    # dataloader
    #scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2017-7529"
    scenario_path = "/home/grimmer/data/LID-DS-2019/CVE-2017-7529/"
    # scenario_path = "/home/grimmer/Work/LID-DS-2021/ZipSlip"
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH)

    # features
    syscall_to_int = IntEmbedding()
    ngram_length = 5
    ngram = Ngram(
        feature_list=[syscall_to_int],
        thread_aware=True,
        ngram_length=ngram_length
    )

    # decision engine (DE)
    # de = Som(epochs=500)
    de = Stide(window_length=1000)

    # the IDS
    ids = IDS(data_loader=dataloader,
              feature_list=[ngram],
              decision_engine=de,
              plot_switch=True)

    print("feature preparation done")
    # training
    ids.train_decision_engine()
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    results = ids.performance.get_performance()
    pprint(results)
    results['ngram'] = ngram_length
    result_path = 'persistent_data/stide.json'
    save_to_json(results, result_path)
    result = load_from_json(result_path)
    pprint(result)
    # draw plot
    # ids.draw_plot()
