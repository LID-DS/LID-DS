import typing

from dataloader.syscall import Syscall
from algorithms.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class ThreadIDExtractor(BaseSyscallFeatureExtractor):

    def extract(self, syscall: Syscall) -> typing.Tuple[str, int]:
        """

        extract thread ID of syscall

        """
        return 'tid', syscall.thread_id()
