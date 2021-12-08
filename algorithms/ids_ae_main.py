from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
import math

if __name__ == '__main__':


    # dataloader
    scenario_path = "/home/grimmer/data/LID-DS-2019/CVE-2017-7529/"
    #scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2017-7529/"
    dataloader = dataloader_factory(scenario_path,direction=Direction.OPEN)

    # this solves LID-DS-2019 CVE-2017-7529 almost perfect:
    # w2v options:
    embedding_size = 5 #dataloader.distinct_syscalls_training_data() #7
    window_size = 10
    epochs = 10000    
    # ngram options:
    ngram_length = 5
    # AE options:
    hidden_size = int(math.sqrt(ngram_length * embedding_size))

    # ------------------------------------------------------------
    # features    
    embedding = W2VEmbedding(
        vector_size=embedding_size,
        window_size=window_size,
        epochs=epochs,
        scenario_path=scenario_path,
        distinct=True,
        thread_aware=True,
        force_train=False
    )
    # embedding = OneHotEncoding()
    ngram = Ngram(
        feature_list=[embedding],
        thread_aware=True,
        ngram_length=ngram_length
    )

    print(f"ngram size          : {ngram_length}")
    print(f"embedding           : {embedding_size}")
    print(f"AE input size       : {ngram_length * embedding_size}")
    print(f"AE hidden layer size: {hidden_size}")
    de = AE(
        input_size = ngram_length * embedding_size,
        hidden_size= hidden_size
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
