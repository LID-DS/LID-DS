import base64

from dataloader.syscall import Syscall
from dataloader.syscall_2019 import Syscall2019

from algorithms.building_block import BuildingBlock


class DataBuffer(BuildingBlock):

    def __init__(self, decode: bool = True):
        super().__init__()
        self._decode = decode

    def _calculate(self, syscall: Syscall):
        """
        extract data buffer of syscall
        """
        data_buffer = syscall.param(param_name='data')
        if data_buffer is not None:
            if type(syscall) is not Syscall2019:
                if self._decode:
                    data_buffer = base64.b64decode(data_buffer)
                    data_buffer = str(data_buffer)
        return data_buffer

    def depends_on(self):
        return []
