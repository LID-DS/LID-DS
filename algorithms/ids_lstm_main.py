from algorithms.features.ngram_plus_next_syscall import NgramPlusNextSyscall
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.threadID import ThreadID
# from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
# from algorithms.features.thread_change_flag import ThreadChangeFlag
from algorithms.features.int_embedding import IntEmbedding
from algorithms.features.w2v_embedding import W2VEmbedding

from algorithms.decision_engines.lstm import LSTM
from algorithms.ids import IDS

from dataloader.dataloader_factory import dataloader_factory
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.direction import Direction

from pprint import pprint

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 3
    embedding_size = 4
    thread_aware = True
    scenario = "Bruteforce_CWE-307"
    scenario_path = f'../../Dataset_old/{scenario}/'
    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)
    syscall_feature_list = [W2VEmbedding(vector_size=embedding_size,
                                         window_size=ngram_length,
                                         epochs=100,
                                         scenario_path=scenario_path,
                                         distinct=False),
                            ThreadID(),
                            IntEmbedding()]
    stream_feature_list = [NgramPlusNextSyscall(feature_list=[W2VEmbedding],
                                                thread_aware=thread_aware,
                                                ngram_length=ngram_length)]

    dataprocessor = DataPreprocessor(dataloader,
                                     syscall_feature_list,
                                     stream_feature_list)
    # decision engine (DE)
    distinct_syscalls = dataloader.distinct_syscalls_training_data()
    lstm = LSTM(ngram_length=ngram_length,
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
              data_preprocessor=dataprocessor,
              decision_engine=lstm,
              plot_switch=False)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint(ids.performance.get_performance())
