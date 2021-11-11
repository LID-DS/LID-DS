from algorithms.features.current_syscall_as_int import CurrentSyscallAsInt
# from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
# from algorithms.features.thread_change_flag import ThreadChangeFlag
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.features.w2v_embedding import W2VEmbedding
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.data_loader_2019 import DataLoader
from algorithms.decision_engines.lstm import LSTM
from score_plot import ScorePlot
from algorithms.ids import IDS

import pprint

if __name__ == '__main__':
    """
    this is an example script to show how to use the LSTM DE with the following settings:

        convert syscall name to vector with length of embedding_size
        create thread aware ngrams of size ngram_length
        ignore current syscall in ngram (NgramMinusOne)
        add current syscall as int with (CurrentSyscallAsInt)
    """
    ngram_length = 4
    embedding_size = 4
    thread_aware = True
    scenario = "CVE-2017-7529"
    scenario_path = f'../../Dataset_old/{scenario}/'
    syscall_feature_list = [W2VEmbedding(vector_size=embedding_size,
                                         window_size=ngram_length,
                                         epochs=100,
                                         scenario_path=scenario_path,
                                         distinct=False),
                            ThreadIDExtractor(),
                            SyscallToInt()]
    stream_feature_list = [NgramMinusOne(feature_list=[W2VEmbedding],
                                         thread_aware=thread_aware,
                                         ngram_length=ngram_length + 1)]
    feature_of_stream_feature_list = [CurrentSyscallAsInt()]

    # data loader for scenario
    dataloader = DataLoader(scenario_path)

    dataprocessor = DataPreprocessor(dataloader,
                                     syscall_feature_list,
                                     stream_feature_list,
                                     feature_of_stream_feature_list)
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
              decision_engine=lstm)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint.pprint(ids.get_performance())

    # creating plot
    plot = ScorePlot(scenario_path=dataloader.scenario_path)

    plot.feed_figure(ids.get_plotting_data())
    plot.show_plot()
