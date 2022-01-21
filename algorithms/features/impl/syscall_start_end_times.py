import sys
import typing
from collections import deque
from collections.abc import Iterable
from enum import Enum

from algorithms.building_block import BuildingBlock
from algorithms.features.impl import threadID
from algorithms.features.impl.threadID import ThreadID
from dataloader.direction import Direction
from dataloader.syscall import Syscall

class StartEndTimesMode(Enum):
    ABSOLUTE_VALUES = 1
    DURATION = 2    

class StartEndTimes(BuildingBlock):
    """
    collects the start and end time of a system call
    data buffer is a dict of dicts
    layer 1 maps thread ids to dicts
    layer 2 maps system call names to system call start times
    if we get a close call and have a matching start time we can return the start time and end time as tuple (start, end) (mode ABSOLUTE_VALUES) or the duration of the call (mod DURATION)
    """

    def __init__(self, mode: StartEndTimesMode = StartEndTimesMode.DURATION):
        """
        """
        super().__init__()
        self._data_buffer = {}
        self._mode = mode

    def depends_on(self):
        return []

    def _calculate(self, syscall: Syscall):
        """
        returns the start and end times of the current syscall if both are collected
        otherwise returns None
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
            # name in dict -> return result if current direction is close
            if syscall.direction() == Direction.CLOSE:                                
                result = (self._data_buffer[thread_id][syscall.name()], syscall.timestamp_unix_in_ns())
                # remove entry from dict
                del self._data_buffer[thread_id][syscall.name()]
                if self._mode == StartEndTimesMode.DURATION:
                    return result[1] - result[0]
                elif self._mode == StartEndTimesMode.ABSOLUTE_VALUES:
                    return result
            else:
                self._data_buffer[thread_id][syscall.name()] = syscall.timestamp_unix_in_ns()
        # finally return None
        return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._data_buffer = {}
