from pprint import pprint

from torch.utils import data
from algorithms.decision_engines.lstm import LSTM

from algorithms.decision_engines.stide import Stide
from algorithms.decision_engines.som import Som
from algorithms.features.impl.average import Average
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    # dataloader
    scenario = "CVE-2017-7529"
    scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2017-7529"
    # scenario_path = "/home/grimmer/data/LID-DS-2019/CVE-2017-7529/"

    dataloader = dataloader_factory(scenario_path,direction=Direction.CLOSE)

    # features
    ngram_length = 3
    embedding_size = 4

    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=10000,
        scenario_path=scenario_path,
        path=f'Models/W2V/',
        force_train=True,
        distinct=True,
        thread_aware=True
    )

    int_embedding = IntEmbedding()
    return_value = ReturnValue()

    ngram = Ngram(
        feature_list=[w2v, return_value],
        thread_aware=True,
        ngram_length=ngram_length + 1
    )

    ngram_minus_one = NgramMinusOne(ngram=ngram, element_size=embedding_size+1)
    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    concat = Concat([int_embedding, ngram_minus_one])

    # decision engine (DE)
    #de = Som(input_vector=ngram, epochs=500)
    de = LSTM(input_vector=concat,
              ngram_length=ngram_length,
              embedding_size=embedding_size,
              distinct_syscalls=distinct_syscalls,
              epochs=20,
              batch_size=256,
              return_value=1,
              time_delta=0,
              thread_change_flag=0,
              force_train=False,
              model_path=f'Models/{scenario}/')
    
    # the IDS
    ids = IDS(data_loader=dataloader,
              resulting_building_block=de,
              plot_switch=False)
   

    print("feature preparation done")
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    pprint(ids.performance.get_performance())
    # draw plot
    ids.draw_plot()
