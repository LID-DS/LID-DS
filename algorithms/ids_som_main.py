from algorithms.decision_engines.stide import Stide
from algorithms.features.path_evilness import PathEvilness
from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.w2v_embedding import W2VEmbedding
from algorithms.decision_engines.som import Som
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader
from dataloader.data_preprocessor import DataPreprocessor

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    # data loader for scenario
    dataloader = DataLoader('/home/felix/repos/LID-DS/LID-DS-2021/CVE-2018-3760')

    # decision engine (DE)
    DE = Som(
        epochs=50
    )

    DE = Stide(3)

    syscall_feature_list = [ThreadIDExtractor(),
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

    syscall_feature_list = [PathEvilness(scenario_path=dataloader.scenario_path)]

    stream_feature_list = [StreamNgramExtractor(feature_list=[PathEvilness],
                                                thread_aware=False,
                                                ngram_length=2)]

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
