from enum import Enum

from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class FDMode(Enum):
    Content = 1
    ID = 2


class FileDescriptor(BuildingBlock, metaclass=Singleton):

    def __init__(self, mode: FDMode):
        super().__init__()
        self._mode = mode

    def _calculate(self, syscall: Syscall):
        """
        calculate process ID of syscall

        Params:
            syscall(Syscall)
        """
        if 'fd' in syscall.params():
            fd = syscall.param('fd')
            fd_parts = fd[:-1].split('(')
            if self._mode == FDMode.ID:
                pass
            elif self._mode == FDMode.Content:
                pass
            else:
                raise ValueError("Invalid Extraction Mode")
        else:
            return None

    def depends_on(self):
        return []
