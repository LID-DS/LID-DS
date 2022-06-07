from datetime import datetime

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class TimeDelta(BuildingBlock):
    """
    calculates the delta to the last systall within the same thread (if thread aware)
    or to the last seen syscall over all
    """

    def __init__(self, thread_aware: bool):
        super().__init__()
        self._max_time_delta = 0
        self._last_time = {}
        self._thread_aware = thread_aware
        self._dependency_list = []
        
    def depends_on(self) -> list:
        return []

    def train_on(self, syscall: Syscall):
        """
        calc max time delta
        """
        current_time = syscall.timestamp_datetime()
        delta = self._calc_delta(current_time, syscall)
        if delta > self._max_time_delta:
            self._max_time_delta = delta

    def fit(self):
        self._last_time = {}

    def _calculate(self, syscall: Syscall):
        """
        calculate time delta of syscall
        """
        current_time = syscall.timestamp_datetime()
        delta = self._calc_delta(current_time, syscall)
        normalized_delta = delta / self._max_time_delta
        return normalized_delta

    def _calc_delta(self, current_time: datetime, syscall: Syscall) -> float:
        """
        calculates the delta to the last systall within the same thread (if thread aware)
        or to the last seen syscall over all
        """
        thread_id = 0
        if self._thread_aware:
            thread_id = syscall.thread_id()
        if thread_id in self._last_time:
            delta = current_time - self._last_time[thread_id]
            delta = delta.total_seconds() * 1000  # delta in microseconds
            self._last_time[thread_id] = current_time
        else:
            delta = 0
            self._last_time[thread_id] = current_time
        return delta
