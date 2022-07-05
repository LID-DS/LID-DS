from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.syscall_name import SyscallName


class IntEmbedding(BuildingBlock):
    """
        convert system call name to unique integer
        
        Params:
        building_block: BB which should be embedded as int
    """

    def __init__(self, building_block: BuildingBlock = None):
        super().__init__()
        self._syscall_dict = {}
        if building_block is None:
            building_block = SyscallName()
        self._dependency_list = [building_block]

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls
        """
        bb_value = self._dependency_list[0].get_result(syscall)
        if bb_value not in self._syscall_dict:
            self._syscall_dict[bb_value] = len(self._syscall_dict) + 1

    def _calculate(self, syscall: Syscall):
        """
            transforms given building_block to integer
        """
        bb_value = self._dependency_list[0].get_result(syscall)
        try:
            sys_to_int = self._syscall_dict[bb_value]
        except KeyError:
            sys_to_int = 0
        return sys_to_int
