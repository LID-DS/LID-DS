import typing

from algorithms.features.base_feature import BaseFeature
from dataloader.syscall import Syscall


class SyscallName(BaseFeature):

    def __init__(self):
        pass

    def extract(self, syscall: Syscall) -> typing.Tuple[int, str]:
        """
        extract name of syscall
        """
        return SyscallName.get_id(), syscall.name()

    def depends_on(self):
        return []
