from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.syscall_int_extractor import SyscallIntExtractor
from algorithms.decision_engines.stide import Stide
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader

from algorithms.features.feature_id_manager import FeatureIDManager

if __name__ == '__main__':
    """

        combination of:
            feature_extractor
            stream_feature_extractor
            decision_engine

    """
    # data loader for scenario
    dataloader = DataLoader('/home/grimmer/Work/LID-DS-2021/CVE-2017-7529/')

    # decision engine (DE)
    stide = Stide()

    # define the used features
    ids = IDS(
        syscall_feature_list=[SyscallIntExtractor(),
                              ThreadIDExtractor()],
        stream_feature_list=[StreamNgramExtractor(feature_list=[SyscallIntExtractor], thread_aware=True, ngram_length=2)],
        data_loader=dataloader,
        decision_engine=stide)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()

    # test feature_id_manager
    print(FeatureIDManager()._feature_to_int_dict)

