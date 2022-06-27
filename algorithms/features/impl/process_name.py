from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class ProcessName(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate name of process
        """
        return syscall.process_name()

    def depends_on(self):
        return []
