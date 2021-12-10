import typing

from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class SyscallName(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def calculate(self, syscall: Syscall, features: dict):
        """
        calculate name of syscall
        """
        features[self.get_id()] = syscall.name()

    def depends_on(self):
        return []
