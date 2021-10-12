import typing

from collections import deque
from algorithms.base_stream_feature_extractor import BaseStreamFeatureExtractor


class StreamNgramExtractor(BaseStreamFeatureExtractor):
    """

    extract ngram form a stream of system call features

    """

    def __init__(self, feature_list: list, thread_aware: bool, ngram_length: int):
        """
        """
        self._ngram_buffer = {}
        self._feature_list = feature_list
        self._thread_aware = thread_aware
        self._ngram_length = ngram_length

    def extract(self, syscall_features: dict) -> typing.Tuple[str, list]:
        """

        only returns not None if ngram exists

        """
        thread_id = 0
        if self._thread_aware:
            try:
                thread_id = syscall_features['tid']
            except Exception:
                raise KeyError('No thread id in features')
        if thread_id not in self._ngram_buffer:
            self._ngram_buffer[thread_id] = deque(maxlen=self._ngram_length)
        self._ngram_buffer[thread_id].append(syscall_features)
        ngram_value = None
        if len(self._ngram_buffer[thread_id]) == self._ngram_length:
            ngram_value = self._collect_features(self._ngram_buffer[thread_id])
        return 'ngram', ngram_value

    def _collect_features(self, queue: deque) -> list:
        """

        creates list of deque of features included in feature_list

        """
        array = []
        for features in queue:
            for feature_name in self._feature_list:
                if feature_name in features:
                    array.append(features[feature_name])
        return array

    def new_recording(self):
        """

        empty buffer so ngrams consist of same recording only

        """
        self._ngram_buffer = {}
