from pprint import pprint

from algorithms.decision_engines.som import Som
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader

if __name__ == '__main__':
    # dataloader
    scenario_path = "/home/grimmer/Work/LID-DS-2021/CVE-2017-7529"
    dataloader = DataLoader(scenario_path)

    # features

    w2v = W2VEmbedding(
        vector_size=5,
        epochs=100,
        path='Models',
        force_train=True,
        distinct=True,
        window_size=10,
        thread_aware=True,
        scenario_path=dataloader.scenario_path)

    pe = PathEvilness(scenario_path=dataloader.scenario_path)

    ngram_length = 7
    ngram = Ngram(feature_list=[w2v], thread_aware=True, ngram_length=ngram_length)

    # decision engine (DE)
    de = Som(epochs=500)
    # de = Stide(window_length=100)

    # the IDS
    ids = IDS(data_loader=dataloader,
              feature_list=[ngram],
              decision_engine=de,
              plot_switch=True)
    # training
    ids.train_decision_engine()
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    pprint(ids.performance.get_performance())
    # draw plot
    ids.draw_plot()
