import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class CollectSyscall(BuildingBlock):
    """
        Summarize information of opening and closing step of syscall.
        Only works if both directions of syscalls are being used in dataloader.

    """

    def __init__(self, feature_list: list):
        """
        Feature: Return syscall only if closing part of syscall is completed.
                 Result of given BBs in input_list for every syscalls are returned.
        """
        super().__init__()
        self._feature_list = feature_list
        self._buffer = {}

        self._dependency_list = []
        self._dependency_list.extend(feature_list)

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        """

        print(self._feature_list)
        for feature in self._feature_list:
            result = feature.get_result(syscall)
            print(result)

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._minimum_values = {}
