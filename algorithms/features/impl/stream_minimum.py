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
        self._dependency_list.append(feature)
        self._feature_id = feature.get_id()

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        returns the minimum value over feature in the window if the feature
        """

        input = self._feature.get_result(syscall)
        if input is not None:
            thread_id = 0
            if self._thread_aware:
                thread_id = syscall.thread_id()
            if thread_id not in self._window_buffer:
                self._window_buffer[thread_id] = deque(maxlen=self._window_length)
                self._minimum_values[thread_id] = math.inf  # max positive value

            check = False
            dropout_value = math.inf
            if len(self._window_buffer[thread_id]) >= self._window_length:
                dropout_value = self._window_buffer[thread_id][0]

            if len(self._window_buffer[thread_id]) == self._window_length:
                check = True            
            self._window_buffer[thread_id].append(input)
            if input < self._minimum_values[thread_id]:
                self._minimum_values[thread_id] = input

            if check and dropout_value <= self._minimum_values[thread_id]:
                self._minimum_values[thread_id] = math.inf
                for item in self._window_buffer[thread_id]:
                    if item < self._minimum_values[thread_id]:
                        self._minimum_values[thread_id] = item

            return self._minimum_values[thread_id]
        else:
            return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._minimum_values = {}
