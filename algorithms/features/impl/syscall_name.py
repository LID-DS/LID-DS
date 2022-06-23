import typing

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class SyscallName(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate name of syscall
        """
        return syscall.name()

    def depends_on(self):
        return []
