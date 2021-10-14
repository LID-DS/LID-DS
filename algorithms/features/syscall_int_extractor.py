import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class SyscallIntExtractor(BaseSyscallFeatureExtractor):

    def __init__(self):
        self._syscall_int_dict = {}

    def extract(self, syscall: Syscall) -> typing.Tuple[int, int]:
        """

        get int from syscall

        """
        if syscall.name() not in self._syscall_int_dict:
            self._syscall_int_dict[syscall.name()] = len(self._syscall_int_dict) + 1

        return SyscallIntExtractor.get_id(), self._syscall_int_dict[syscall.name()]
