import typing

from dataloader.syscall import Syscall
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class TimeDeltaSyscalls(BaseSyscallFeatureExtractor):
    """

        calculate biggest time delta between syscalls
        (either to last syscall in same thread or thread unaware)
        needs ThreadID feature

    """

    def __init__(self, thread_aware: bool):
        super().__init__()
        self._max_time_delta = 0
        self._last_time = {}
        self._thread_aware = thread_aware

    def train_on(self, syscall: Syscall):
        """

            save current time of timestamp

        """
        current_time = syscall.timestamp_datetime()
        time_delta = 0
        threadID = 0
        if self._thread_aware:
            threadID = syscall.thread_id()
        if threadID in self._last_time:
            time_delta = current_time - self._last_time[threadID]
            self._last_time[threadID] = current_time
        else:
            self._last_time[threadID] = current_time
        if time_delta != 0:
            time_delta = time_delta.microseconds
        if time_delta > self._max_time_delta:
            self._max_time_delta = time_delta

    def extract(self, syscall: Syscall) -> typing.Tuple[str, float]:
        """

            calc normalized time_delta

        """
        current_time = syscall.timestamp_datetime()
        time_delta = 0
        threadID = 0
        if self._thread_aware:
            threadID = syscall.thread_id()
        if self._last_time[threadID] is not None:
            time_delta = current_time - self._last_time[threadID]
            self._last_time[threadID] = current_time
        else:
            self._last_time[threadID] = current_time
        if time_delta != 0:
            time_delta = time_delta.microseconds
        normalized_time_delta = time_delta / self._max_time_delta
        return TimeDeltaSyscalls.get_id(), normalized_time_delta
