import typing

from datetime import datetime

from dataloader.syscall import Syscall
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class TimeDelta(BaseSyscallFeatureExtractor):

    def __init__(self, thread_aware: bool):
        super().__init__()
        self._max_time_delta = 0
        self._last_time = {}
        self._thread_aware = thread_aware

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

    def extract(self, syscall: Syscall) -> typing.Tuple[int, float]:
        """

        extract thread ID of syscall

        """
        current_time = syscall.timestamp_datetime()
        delta = self._calc_delta(current_time, syscall)
        normalized_delta = delta / self._max_time_delta
        return TimeDelta.get_id(), normalized_delta

    def _calc_delta(self, current_time: datetime, syscall: Syscall) -> float:
        thread_id = 0
        if self._thread_aware:
            thread_id = syscall.thread_id()
        if thread_id in self._last_time:
            delta = current_time - self._last_time[thread_id]
            delta = delta.microseconds
            self._last_time[thread_id] = current_time
        else:
            delta = 0
            self._last_time[thread_id] = current_time
        return delta
