import pprint

from algorithms.features.ngram import Ngram
from algorithms.features.threadID import ThreadID
from algorithms.features.w2v_embedding import W2VEmbedding
from algorithms.decision_engines.som import Som
from algorithms.ids import IDS
from algorithms.score_plot import ScorePlot
from dataloader.data_loader_2019 import DataLoader2019
from algorithms.data_preprocessor import DataPreprocessor

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    # data loader for scenario
    dataloader = DataLoader2019('/home/felix/repos/LID-DS/LID-DS-2019/CVE-2017-7529')

    # decision engine (DE)
    DE = Som(
        epochs=50
    )

    syscall_feature_list = [ThreadID(),
                            W2VEmbedding(
                                vector_size=5,
                                epochs=50,
                                path='Models',
                                force_train=True,
                                distinct=True,
                                window_size=7,
                                thread_aware=True,
                                scenario_path=dataloader.scenario_path)
                            ]

    stream_feature_list = [Ngram(feature_list=[W2VEmbedding],
                                 thread_aware=False,
                                 ngram_length=7)]

    dataprocessor = DataPreprocessor(dataloader,
                                     syscall_feature_list,
                                     stream_feature_list)

    # define the used features
    ids = IDS(data_loader=dataloader,
              data_preprocessor=dataprocessor,
              decision_engine=DE)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    DE.show_distance_plot()

    pprint.pprint(ids.get_performance())

    # creating plot
    plot = ScorePlot(scenario_path=dataloader.scenario_path)

    plot.feed_figure(ids.get_plotting_data())
    plot.show_plot()
