import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class StreamProduct(BuildingBlock):
    """
    gives the product of all values from a stream of building blocks
    """

    def __init__(self, feature: BuildingBlock, thread_aware: bool, window_length: int):
        """
        feature: the product should be calculated on feature
        thread_aware: True or False
        window_length: length of the window considered
        """
        super().__init__()
        self._window_buffer = {}
        self._feature = feature
        self._thread_aware = thread_aware
        self._window_length = window_length

        self._dependency_list = []
        self._dependency_list.append(feature)
        self._feature_id = feature.get_id()

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, features: dict):
        """
        returns the product over feature in the window if the feature is in the current set of features
        """
        thread_id = 0
        if self._thread_aware:
            thread_id = syscall.thread_id()
        if thread_id not in self._window_buffer:
            self._window_buffer[thread_id] = deque(maxlen=self._window_length)

        if self._feature_id in features:            
            new_value = features[self._feature_id]
            self._window_buffer[thread_id].append(new_value)            
            tmp=1.0
            for v in self._window_buffer[thread_id]:
                tmp *= v            
            features[self.get_id()] = tmp

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._product_values = {}
