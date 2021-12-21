import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class StreamMinimum(BuildingBlock):
    """
    gives the minimum value from a stream of system call features
    """

    def __init__(self, feature: BuildingBlock, thread_aware: bool, window_length: int):
        """
        feature: the minimum should be calculated on feature
        thread_aware: True or False
        window_length: length of the window considered
        """
        super().__init__()
        self._window_buffer = {}
        self._minimum_values = {}
        self._feature = feature
        self._thread_aware = thread_aware
        self._window_length = window_length

        self._dependency_list = []
        if thread_aware:
            self._dependency_list.append(ThreadID())
        self._dependency_list.append(feature)
        self._feature_id = feature.get_id()

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, features: dict):
        """
        returns the minimum value over feature in the window if the feature is in the current set of features
        """
        thread_id = 0
        if self._thread_aware:
            try:
                thread_feature_id = ThreadID().get_id()
                thread_id = features[thread_feature_id]
            except Exception:
                raise KeyError('No thread id in features')
        if thread_id not in self._window_buffer:
            self._window_buffer[thread_id] = deque(maxlen=self._window_length)
            self._minimum_values[thread_id] = math.inf  # max positive value

        if self._feature_id in features:
            check = False
            dropout_value = math.inf
            if len(self._window_buffer[thread_id]) > 0:
                dropout_value = self._window_buffer[thread_id][0]

            if len(self._window_buffer[thread_id]) == self._window_length:
                check = True
            new_value = features[self._feature_id]
            self._window_buffer[thread_id].append(new_value)
            if new_value < self._minimum_values[thread_id]:
                self._minimum_values[thread_id] = new_value

            if check and dropout_value <= self._minimum_values[thread_id]:
                self._minimum_values[thread_id] = math.inf
                for item in self._window_buffer[thread_id]:
                    if item < self._minimum_values[thread_id]:
                        self._minimum_values[thread_id] = item

            minimum_value = self._minimum_values[thread_id]
            features[self.get_id()] = minimum_value

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._minimum_values = {}
