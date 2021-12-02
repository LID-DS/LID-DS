# from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.ngram import Ngram

from dataloader.data_loader_2019 import DataLoader

from algorithms.decision_engines.lstm import LSTM

from algorithms.ids import IDS

from pprint import pprint

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 3
    embedding_size = 4
    thread_aware = True
    scenario = "CVE-2014-0160"
    scenario_path = f'../../Dataset_old/{scenario}/'

    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)

    w2v = W2VEmbedding(
        vector_size=embedding_size,
        window_size=10,
        epochs=5000,
        scnenario_path=scenario_path,
        path=f'Models/{scenario}/W2V/',
        force_train=True,
        distinct=True,
        thread_aware=True
    )
    return_value = ReturnValue()
    ngram = Ngram(
        feature_list=[w2v],
        thread_aware=thread_aware,
        ngram_length=ngram_length
    )
    ngram_minus_one = NgramMinusOne(
        ngram,
        embedding_size
    )
    int_embedding = IntEmbedding()

    # decision engine (DE)
    distinct_syscalls = dataloader.distinct_syscalls_training_data()
    lstm = LSTM(ngram_length=ngram_length,
                embedding_size=embedding_size,
                distinct_syscalls=distinct_syscalls,
                epochs=20,
                batch_size=256,
                force_train=False,
                model_path=f'Models/{scenario}/',
                time_delta=0,
                thread_change_flag=1,
                return_value=1)

    # define the used features
    ids = IDS(data_loader=dataloader,
              feature_list=[int_embedding,
                            ngram_minus_one,
                            thread_change_flag],
              decision_engine=lstm,
              plot_switch=True)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint(ids.performance.get_performance())
