from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.decision_engines.stide import Stide
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from dataloader.data_preprocessor import DataPreprocessor
import pprint
from plot import ExploitPlot

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """

    syscall_feature_list = [SyscallToInt(),
                            ThreadIDExtractor()]
    stream_feature_list = [StreamNgramExtractor(feature_list=[SyscallToInt],
                                                thread_aware=True,
                                                ngram_length=5)]

    # data loader for scenario
    dataloader = DataLoader('/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529')

    dataprocessor = DataPreprocessor(dataloader,
                                     syscall_feature_list,
                                     stream_feature_list)
    # decision engine (DE)
    stide = Stide(window_length=50)

    # define the used features
    ids = IDS(data_loader=dataloader,
              data_preprocessor=dataprocessor,
              decision_engine=stide)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint.pprint(ids.get_performance())

    plot = ExploitPlot(ids.get_plotting_data(), dataloader)

    plot.plot_performance()

