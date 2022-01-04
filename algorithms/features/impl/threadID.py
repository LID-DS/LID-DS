from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ThreadID(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        calculate thread ID of syscall
        """
        dependencies[self.get_id()] = syscall.thread_id()

    def depends_on(self):
        return []
