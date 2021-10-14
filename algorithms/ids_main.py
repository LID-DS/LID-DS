from algorithms.decision_engines.example_decision_engine import ExampleDecisionEngine
from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.word_embedding import WordEmbedding
from algorithms.ids import IDS
from dataloader.data_loader import DataLoader

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
    example_de = ExampleDecisionEngine()

    # define the used features
    ids = IDS(
        syscall_feature_list=[WordEmbedding(window=5, vector_size=1, thread_aware=True),
                              ThreadIDExtractor()],
        stream_feature_list=[StreamNgramExtractor(feature_list=[WordEmbedding], thread_aware=True, ngram_length=2)],
        data_loader=dataloader,
        decision_engine=example_de)

    ids.train_decision_engine()
    ids.determine_threshold()
    ids.do_detection()
