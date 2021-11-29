from pprint import pprint

from algorithms.decision_engines.som import Som
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.average import Average
from algorithms.features.impl.flags import Flags
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.maximum import Maximum
from algorithms.features.impl.minimum import Minimum
from algorithms.features.impl.mode import Mode
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.path_length import PathLength
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader

if __name__ == '__main__':
    # dataloader
    #scenario_path = "/home/grimmer/Work/LID-DS-2021/CVE-2017-7529"
    #scenario_path = "/home/grimmer/Work/LID-DS-2021/Bruteforce_CWE-307"
    scenario_path = "/home/grimmer/Work/LID-DS-2021/ZipSlip"
    dataloader = DataLoader(scenario_path)

    # features

    # w2v = W2VEmbedding(
    #     vector_size=5,
    #     epochs=500,
    #     path='Models',
    #     force_train=False,
    #     distinct=True,
    #     window_size=10,
    #     thread_aware=True,
    #     scenario_path=dataloader.scenario_path)

    # plen = PathLength()

    ngram_length = 7
    #ngram = Ngram(feature_list=[IntEmbedding()], thread_aware=True, ngram_length=ngram_length)
    ngram = Ngram(feature_list=[IntEmbedding(),Flags(),Mode()], thread_aware=True, ngram_length=ngram_length)

    # decision engine (DE)
    #de = Som(epochs=500)
    de = Stide(window_length=100)

    # the IDS
    ids = IDS(data_loader=dataloader,
              feature_list=[ngram],
              decision_engine=de,
              plot_switch=False)
    print("feature preparation done")
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
