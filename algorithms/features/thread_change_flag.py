import typing
from collections import deque
from collections.abc import Iterable

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class ThreadChangeFlag(BaseSyscallFeatureExtractor):
    """

    extract ngram form a stream of system call features

    """

    def __init__(self, thread_aware: bool):
        """

        feature list defines which features to include
        first appearance of syscall_features sets thread_change_flag to 1

        """
        self._last_thread = None
        pass

    def extract(self, syscall: Syscall) -> typing.Tuple[int, list]:
        """

        only returns not None if ngram exists

        """
        current_thread = syscall.thread_id()
        # print(syscall.name())
        if self._last_thread == current_thread:
            thread_change_flag = 0
        else:
            # print('one')
            thread_change_flag = 1
            self._last_thread = current_thread
        return ThreadChangeFlag.get_id(), [thread_change_flag]
