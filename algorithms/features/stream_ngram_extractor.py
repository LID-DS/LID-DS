import typing
from collections import deque

from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from collections.abc import Iterable


class StreamNgramExtractor(BaseStreamFeatureExtractor):
    """

    extract ngram form a stream of system call features

    """

    def __init__(self, feature_list: list, thread_aware: bool, ngram_length: int):
        """
        """
        super().__init__()
        self._ngram_buffer = {}
        self._list_of_feature_ids = []
        for feature_class in feature_list:
            self._list_of_feature_ids.append(feature_class.get_id())
        self._thread_aware = thread_aware
        self._ngram_length = ngram_length

    def extract(self, syscall_features: dict) -> typing.Tuple[int, list]:
        """

        only returns not None if ngram exists

        """
        thread_id = 0
        if self._thread_aware:
            try:
                thread_id = syscall_features[ThreadIDExtractor.get_id()]
            except Exception:
                raise KeyError('No thread id in features')
        if thread_id not in self._ngram_buffer:
            self._ngram_buffer[thread_id] = deque(maxlen=self._ngram_length)
        self._ngram_buffer[thread_id].append(syscall_features)
        ngram_value = None
        if len(self._ngram_buffer[thread_id]) == self._ngram_length:

            ngram_value = self._collect_features(self._ngram_buffer[thread_id])

        return StreamNgramExtractor.get_id(), ngram_value

    def _collect_features(self, deque_of_dicts: deque) -> list:
        """
        in:  a deque of dictionaries like {feature_id_1: value_1, feature_id_2: value_2}
        out: the ngram consisting of the selected features

        """
        array = []
        for feature_dict in deque_of_dicts:
            for feature_id in self._list_of_feature_ids:
                if feature_id in feature_dict:
                    if isinstance(feature_dict[feature_id], Iterable):
                        array += feature_dict[feature_id]
                    else:
                        array.append(feature_dict[feature_id])

        return array

    def new_recording(self):
        """

        empty buffer so ngrams consist of same recording only

        """
        self._ngram_buffer = {}
