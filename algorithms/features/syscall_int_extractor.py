import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class SyscallIntExtractor(BaseSyscallFeatureExtractor):
    """

        base class for feature transformation e.g. embedding process

    """

    def __init__(self):
        self._syscall_dict = {}

    def train_on(self, syscall: Syscall):
        """

            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls

        """
        if syscall.name() not in self._syscall_dict:
            self._syscall_dict[syscall.name()] = len(self._syscall_dict) + 1

    def extract(self, syscall: Syscall) -> typing.Tuple[str, list]:
        """

            transforms given syscall name to integer

        """
        try:
            sys_to_int = self._syscall_dict[syscall.name()]
        except KeyError:
            sys_to_int = 0
        return SyscallIntExtractor.get_id(), [sys_to_int]
