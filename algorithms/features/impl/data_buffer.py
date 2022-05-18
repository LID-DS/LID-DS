import typing

from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall
from dataloader.syscall_2019 import Syscall2019
from dataloader.syscall_2021 import Syscall2021


class DataBuffer(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        extract data buffer of syscall
        """
        data_buffer = syscall.param(param_name='data')
        return data_buffer 

    def depends_on(self):
        return []
