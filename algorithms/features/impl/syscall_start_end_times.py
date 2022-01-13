import sys
import typing
from collections import deque
from collections.abc import Iterable

from algorithms.building_block import BuildingBlock
from algorithms.features.impl import threadID
from algorithms.features.impl.threadID import ThreadID
from dataloader.direction import Direction
from dataloader.syscall import Syscall


class StartEndTimes(BuildingBlock):
    """
    collects the start and end time of a system call
    data buffer is a dict of dicts
    layer 1 maps thread ids to dicts
    layer 2 maps system call names to system call start times
    if we get a close call and have a matching start time we can write the start time and end time into the result dict
    """

    def __init__(self):
        """
        """
        super().__init__()
        self._data_buffer = {}

    def depends_on(self):
        return []

    def _calculate(self, syscall: Syscall, dependencies: dict):
        """
        writes the start and end times of the current syscall if both are collected
        otherwise does not write into dependencies
        """
        # check for thread id
        thread_id = syscall.thread_id()
        if thread_id not in self._data_buffer:
            self._data_buffer[thread_id] = {}
        # check for syscall name
        if syscall.name() not in self._data_buffer[thread_id]:
            # name not in dict -> insert its time if its an opening call
            if syscall.direction() == Direction.OPEN:
                self._data_buffer[thread_id][syscall.name()] = syscall.timestamp_unix_in_ns()
            # if direction == CLOSE: do nothing
        else:
            # name in dict -> write to results if current direction is close
            if syscall.direction() == Direction.CLOSE:
                dependencies[self.get_id()] = (self._data_buffer[thread_id][syscall.name()], syscall.timestamp_unix_in_ns())
                print(f"  {syscall.name()} -> {self._data_buffer[thread_id][syscall.name()]}, {syscall.timestamp_unix_in_ns()}")
                # remove entry from dict
                del self._data_buffer[thread_id][syscall.name()]
            else:
                self._data_buffer[thread_id][syscall.name()] = syscall.timestamp_unix_in_ns()

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._data_buffer = {}
