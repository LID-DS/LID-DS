import typing
from collections import deque
from collections.abc import Iterable

from algorithms.features.base_feature import BaseFeature
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class Ngram(BaseFeature):
    """
    extract ngram form a stream of system call features
    """

    def __init__(self, feature_list: list, thread_aware: bool, ngram_length: int):
        """
        feature_list: list of features the ngram should use
        thread_aware: True or False
        ngram_length: length of the ngram
        """
        super().__init__()
        self._ngram_buffer = {}
        self._list_of_feature_ids = []
        for feature in feature_list:
            self._list_of_feature_ids.append(feature.get_id())
        self._thread_aware = thread_aware
        self._ngram_length = ngram_length

        self._dependency_list = []
        if thread_aware:
            self._dependency_list.append(ThreadID())
        self._dependency_list.extend(feature_list)

    def depends_on(self):
        return self._dependency_list

    def extract(self, syscall: Syscall, features: dict):
        """
        return None if the ngram is not complete
        otherwise the ngram is returned
        """
        thread_id = 0
        if self._thread_aware:
            try:
                thread_id = features[ThreadID().get_id()]
            except Exception:
                raise KeyError('No thread id in features')
        if thread_id not in self._ngram_buffer:
            self._ngram_buffer[thread_id] = deque(maxlen=self._ngram_length)
        self._ngram_buffer[thread_id].append(features)
        ngram_value = None
        if len(self._ngram_buffer[thread_id]) == self._ngram_length:
            ngram_value = self._collect_features(self._ngram_buffer[thread_id])

        features[self.get_id()] = ngram_value

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
                        if isinstance(feature_dict[feature_id], str):
                            array.append(feature_dict[feature_id])
                        else:
                            array.extend(feature_dict[feature_id])
                    else:
                        array.append(feature_dict[feature_id])
        return array

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._ngram_buffer = {}
