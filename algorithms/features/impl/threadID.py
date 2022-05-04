from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ThreadID(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate thread ID of syscall
        """
        return syscall.thread_id()

    def depends_on(self):
        return []
