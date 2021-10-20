from algorithms.features.stream_ngram_plus_next_syscall import NgramPlusNextSyscall
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.features.w2v_embedding import W2VEmbedding
from algorithms.decision_engines.lstm import LSTM
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from dataloader.data_preprocessor import DataPreprocessor

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 4
    embedding_size = 4
    scenario_path = '../../Dataset/CVE-2017-7529/'
    syscall_feature_list = [W2VEmbedding(vector_size=embedding_size,
                                         window_size=ngram_length,
                                         epochs=100,
                                         scenario_path=scenario_path,
                                         distinct=False),
                            ThreadIDExtractor(),
                            SyscallToInt()]
    stream_feature_list = [NgramPlusNextSyscall(feature_list=[W2VEmbedding, SyscallToInt],
                                                thread_aware=True,
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
                epochs=100)

    # define the used features
    ids = IDS(data_loader=dataloader,
              data_preprocessor=dataprocessor,
              decision_engine=lstm)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
