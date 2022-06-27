from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class ProcessID(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate process ID of syscall

        Params:
            syscall(Syscall)
        """
        return syscall.process_id()

    def depends_on(self):
        return []
