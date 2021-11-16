import typing
from collections import deque

from algorithms.features.threadID import ThreadID
from algorithms.features.int_embedding import IntEmbedding
from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor


class NgramPlusNextSyscall(BaseStreamFeatureExtractor):
    """
    extract ngram form a stream of system call features
    include n+1 system call as integer vor supervised learning
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

    def extract(self, syscall_features: dict) -> typing.Tuple[str, list]:
        """
        only returns not None if ngram exists
        """
        # get current threadID of syscall
        thread_id = 0
        if self._thread_aware:
            try:
                thread_id = syscall_features[ThreadID.get_id()]
            except Exception:
                raise KeyError('No thread id in features')
        # if current buffer for thread is full append syscall integer
        # to ngram_value which later can be used as x, y for DE input
        ngram_value = None
        if thread_id in self._ngram_buffer:
            if len(self._ngram_buffer[thread_id]) == self._ngram_length:
                ngram_value = self._collect_features(self._ngram_buffer[thread_id])
                ngram_value = syscall_features[IntEmbedding.get_id()] + ngram_value
        # but also add syscall to buffer
        if thread_id not in self._ngram_buffer:
            self._ngram_buffer[thread_id] = deque(maxlen=self._ngram_length)
        self._ngram_buffer[thread_id].append(syscall_features)
        return NgramPlusNextSyscall.get_id(), ngram_value

    def _collect_features(self, deque_of_dicts: deque) -> list:
        """
        creates list of deque of features included in feature_list
        """
        array = []
        for feature_dict in deque_of_dicts:
            for feature_id in self._list_of_feature_ids:
                if feature_id in feature_dict:
                    array.extend(feature_dict[feature_id])
        return array

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._ngram_buffer = {}
