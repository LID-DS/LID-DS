from algorithms.word_embedding import WordEmbedding
from algorithms.threadID_extractor import ThreadIDExtractor
from algorithms.stream_ngram_extractor import StreamNgramExtractor
from algorithms.example_decision_engine import ExampleDecisionEngine

from dataloader.data_loader import DataLoader

from dataloader.syscall import Syscall


def feature_extractor(syscall: Syscall,
                      feature_extractors: list) -> list:
    feature_dict = {}
    for feature in feature_extractors:
        k, v = feature.extract(syscall)
        feature_dict[k] = v
    return feature_dict


def stream_feature_extractor(feature_dict: dict,
                             stream_feature_extractors: list) -> list:
    stream_feature_dict = {}
    for sfe in stream_feature_extractors:
        k, v = sfe.extract(feature_dict)
        if v is not None:
            stream_feature_dict[k] = v
    extracted_feature_list = []
    for key in stream_feature_dict.keys():
        extracted_feature_list += stream_feature_dict[key]
    return extracted_feature_list


if __name__ == '__main__':
    """

        combination of:
            feature_extractor
            stream_feature_extractor
            decision_engine

    """

    w2v_extractor = WordEmbedding(window=4,
                                  vector_size=2,
                                  thread_aware=True)
    tid_extractor = ThreadIDExtractor()

    FE = [w2v_extractor, tid_extractor]

    ngram_extractor = StreamNgramExtractor(feature_list=['w2v'],
                                           thread_aware=True,
                                           ngram_length=4)
    SFE = [ngram_extractor]

    example_de = ExampleDecisionEngine()

    # prepare example scenario
    data_loader = DataLoader('../../Dataset/CVE-2017-7529/')

    # train FEs
    training_data = data_loader.training_data()
    for recording in training_data:
        for syscall in recording.syscalls():
            for fe in FE:
                fe.train_on(syscall)

    # fit FEs
    for fe in FE:
        fe.fit()

    # train SFEs
    training_data = data_loader.training_data()
    for recording in training_data:
        for syscall in recording.syscalls():
            feature_dict = feature_extractor(syscall, FE)
            for sfe in SFE:
                sfe.train_on(feature_dict)

    # fit SFEs
    for sfe in SFE:
        sfe.fit()

    # train of DE
    for recording in training_data:
        for syscall in recording.syscalls():
            # preprocessing
            feature_dict = feature_extractor(syscall, FE)
            stream_feature_list = stream_feature_extractor(feature_dict, SFE)
            if len(stream_feature_list) > 0:
                example_de.train_on(stream_feature_list)
    example_de.fit()

    # detection
    for recording in data_loader.validation_data():
        for syscall in recording.syscalls():
            # preprocessing
            feature_dict = feature_extractor(syscall, FE)
            stream_feature_list = stream_feature_extractor(feature_dict, SFE)
            if len(stream_feature_list) > 0:
                prediction = example_de.predict(stream_feature_list)
                print(prediction)
