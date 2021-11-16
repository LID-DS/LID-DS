from algorithms.features.ngram import Ngram
from algorithms.features.threadID import ThreadID
from algorithms.features.int_embedding import IntEmbedding
from algorithms.decision_engines.stide import Stide
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from dataloader.data_preprocessor import DataPreprocessor
from pprint import pprint


if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    
    """

    syscall_feature_list = [IntEmbedding(),
                            ThreadID()]
    stream_feature_list = [Ngram(feature_list=[IntEmbedding],
                                 thread_aware=True,
                                 ngram_length=5)]

    # data loader for scenario
    dataloader = DataLoader('/home/eschulze/LID-DS-2021/CVE-2017-7529')

    dataprocessor = DataPreprocessor(dataloader,
                                     syscall_feature_list,
                                     stream_feature_list)
    # decision engine (DE)
    stide = Stide(window_length=50)

    # define the used features
    ids = IDS(data_loader=dataloader,
              data_preprocessor=dataprocessor,
              decision_engine=stide,
              plot_switch=True)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    pprint(ids.performance.get_performance())

    # plotting / save_plot() must be called before show_plot()
    ids.plot.feed_figure()
    ids.plot.show_plot()

