import typing

from dataloader.syscall import Syscall
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class SyscallName(BaseSyscallFeatureExtractor):

    def extract(self, syscall: Syscall) -> typing.Tuple[int, list]:
        """
        extract name of syscall
        """
        return SyscallName.get_id(), [syscall.name()]
