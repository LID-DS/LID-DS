import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class ThreadIDExtractor(BaseSyscallFeatureExtractor):

    def extract(self, syscall: Syscall) -> typing.Tuple[int, int]:
        """

        extract thread ID of syscall

        """
        return ThreadIDExtractor.get_id(), syscall.thread_id()

    def new_recording(self):
        pass
