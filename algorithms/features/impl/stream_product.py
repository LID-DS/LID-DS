import math
from collections import deque
import sys

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

    def _calculate(self, syscall: Syscall):
        """
        returns the product over feature in the window, if the feature is not None and the window is full
        otherwise: None
        """
        input = self._feature.get_result(syscall)
        if input is not None:
            thread_id = 0
            if self._thread_aware:
                thread_id = syscall.thread_id()
            if thread_id not in self._window_buffer:
                self._window_buffer[thread_id] = deque(maxlen=self._window_length)            
            self._window_buffer[thread_id].append(input)            
            if len(self._window_buffer[thread_id]) < self._window_length:
                return None
            tmp=1.0
            for v in self._window_buffer[thread_id]:
                tmp *= v            
            return tmp
        else:
            return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._product_values = {}
