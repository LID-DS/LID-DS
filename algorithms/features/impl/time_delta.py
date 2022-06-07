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
        current_time = syscall.timestamp_unix_in_ns()
        thread_id = 0
        if self._thread_aware:
            thread_id = syscall.thread_id()
        delta = self._calc_delta(current_time, thread_id)
        if delta > self._max_time_delta:
            self._max_time_delta = delta

    def fit(self):
        self._last_time = {}

    def _calculate(self, syscall: Syscall):
        """
        calculate time delta of syscall
        """
        current_time = syscall.timestamp_unix_in_ns()
        thread_id = 0
        if self._thread_aware:
            thread_id = syscall.thread_id()
        delta = self._calc_delta(current_time, thread_id)
        normalized_delta = delta / self._max_time_delta
        return normalized_delta

    def _calc_delta(self, current_time: int, thread_id: int):
        if thread_id in self._last_time:
            delta = current_time - self._last_time[thread_id]
            self._last_time[thread_id] = current_time
        else:
            delta = 0
            self._last_time[thread_id] = current_time
        return delta
