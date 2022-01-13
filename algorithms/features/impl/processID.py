from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ProcessID(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate process ID of syscall
        """
        return syscall.process_id()

    def depends_on(self):
        return []
