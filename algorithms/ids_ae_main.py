from pprint import pprint
from torch.utils import data
from algorithms.decision_engines.ae import AE
from algorithms.features.impl.average import Average
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
import math

if __name__ == '__main__':
    # dataloader
    scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2017-7529"
    #scenario_path = "/home/grimmer/data/LID-DS-2021/Bruteforce_CWE-307"
    #scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2020-23839"
    #scenario_path = "/home/grimmer/data/LID-DS-2019/CVE-2017-7529/"
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH)

    # features
    embedding_size = 5
    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=100,
        scenario_path=scenario_path,
        distinct=True,
        thread_aware=True,
        force_train=False
    )

    ngram_length = 3
    ngram = Ngram(
        feature_list=[w2v,ReturnValue()],
        thread_aware=True,
        ngram_length=ngram_length
    )

    print(f"ngram size : {ngram_length}")
    print(f"embedding  : {embedding_size}")
    print(f"input size : {ngram_length * embedding_size}")
    print(f"hidden size: {int(math.sqrt(ngram_length * embedding_size))}")
    de = AE(
        input_size = ngram_length * embedding_size,
        hidden_size= int(math.sqrt(ngram_length * embedding_size))
    )

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
