from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.w2v_embedding import W2VEmbedding
from algorithms.features.path_evilness import PathEvilness
from algorithms.features.syscall_int_extractor import SyscallIntExtractor
from algorithms.decision_engines.som import Som
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    # data loader for scenario
    dataloader = DataLoader('/home/felix/repos/LID-DS/LID-DS-2021/CVE-2014-0160')

    # decision engine (DE)
    DE = Som(
        epochs=50
    )

    # define the used features
    ids = IDS(
        syscall_feature_list=[W2VEmbedding(
            vector_size=5,
            epochs=50,
            path='Models',
            force_train=True,
            distinct=True,
            window_size=7,
            thread_aware=True,
            scenario_path=dataloader._scenario_path
        ), ThreadIDExtractor(), PathEvilness()],
        stream_feature_list=[StreamNgramExtractor(feature_list=[W2VEmbedding],
                                                  thread_aware=True,
                                                  ngram_length=2)],
        data_loader=dataloader,
        decision_engine=DE)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
    DE.show_distance_plot()
