from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.ngram import Ngram
# from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
# from algorithms.features.thread_change_flag import ThreadChangeFlag

from algorithms.decision_engines.lstm import LSTM
from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from algorithms.data_preprocessor import DataPreprocessor
from dataloader.direction import Direction

from pprint import pprint

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 3
    embedding_size = 4
    thread_aware = True
    scenario = "CVE-2017-7529"
    scenario_path = f'../../Dataset/{scenario}/'

    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)

    # embedding
    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=5000,
        scenario_path=scenario_path,
        path=f'Models/{scenario}/W2V/',
        force_train=True,
        distinct=True,
        thread_aware=thread_aware
    )
    int_embedding = IntEmbedding()

    # extra parameter
    return_value = ReturnValue()

    # ngrams
    ngram = Ngram(feature_list=[w2v, return_value],
                  thread_aware=True,
                  ngram_length=ngram_length + 1
                  )
    ngram_minus_one = NgramMinusOne(ngram=ngram,
                                    element_size=embedding_size + 1)  # plus 1 for return value

    # decision engine (DE)
    distinct_syscalls = dataloader.distinct_syscalls_training_data()
    de = LSTM(ngram_length=ngram_length,
              embedding_size=embedding_size,
              distinct_syscalls=distinct_syscalls,
              epochs=20,
              batch_size=256,
              return_value=1,
              time_delta=0,
              thread_change_flag=0,
              force_train=False,
              model_path=f'Models/{scenario}/')

    # define the used features
    ids = IDS(data_loader=dataloader,
              resulting_building_block=[int_embedding, ngram_minus_one],
              decision_engine=de,
              plot_switch=False)

    # training
    ids.train_decision_engine()
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print(results)
    pprint(ids.performance.get_performance())
