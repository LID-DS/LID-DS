from algorithms.features.ngram_plus_next_syscall import NgramPlusNextSyscall
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.threadID_extractor import ThreadIDExtractor
# from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
# from algorithms.features.thread_change_flag import ThreadChangeFlag
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.features.w2v_embedding import W2VEmbedding
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.data_loader_2019 import DataLoader
from algorithms.decision_engines.lstm import LSTM
from algorithms.ids import IDS
from score_plot import ScorePlot

import pprint

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 3
    embedding_size = 4
    thread_aware = True
    scenario = "CVE-2014-0160"
    scenario_path = f'../../Dataset_old/{scenario}/'
    syscall_feature_list = [W2VEmbedding(vector_size=embedding_size,
                                         window_size=ngram_length,
                                         epochs=100,
                                         scenario_path=scenario_path,
                                         distinct=False),
                            ThreadIDExtractor(),
                            SyscallToInt()]
    stream_feature_list = [NgramPlusNextSyscall(feature_list=[W2VEmbedding],
                                                thread_aware=thread_aware,
                                                ngram_length=ngram_length)]

    # data loader for scenario
    dataloader = DataLoader(scenario_path)

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
                force_train=False,
                model_path=f'Models/{scenario}/')
                # time_delta=0,
                # thread_change_flag=0,
                # return_value=0)

    # define the used features
    ids = IDS(data_loader=dataloader,
              data_preprocessor=dataprocessor,
              decision_engine=lstm,
              plot_switch=True)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint(ids.performance.get_performance())

    # plotting / save_plot() must be called before show_plot()
    ids.plot.feed_figure()
    ids.plot.show_plot()
