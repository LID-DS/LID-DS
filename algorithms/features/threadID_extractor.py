import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class ThreadIDExtractor(BaseSyscallFeatureExtractor):

    def extract(self, syscall: Syscall) -> typing.Tuple[str, int]:
        """

        extract thread ID of syscall

        """
        return 'tid', syscall.thread_id()
