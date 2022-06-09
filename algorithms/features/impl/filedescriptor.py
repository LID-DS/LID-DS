import re
from enum import IntEnum

from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class FDMode(IntEnum):
    ID = 0
    Content = 1


class FileDescriptor(BuildingBlock, metaclass=Singleton):

    def __init__(self, mode: FDMode):
        super().__init__()
        self._mode = mode

    def _calculate(self, syscall: Syscall):
        """
        calculate file descriptor of syscall

        Params:
            syscall(Syscall)
        """
        params = syscall.params()
        if 'fd' in params:
            return self._get_fd_part(syscall.param('fd'), self._mode)
        elif 'in_fd' in params:
            if 'out_fd' in params:
                return self._get_fd_part(syscall.param('in_fd'), self._mode) + self._get_fd_part(
                    syscall.param('out_fd'), self._mode)
            else:
                return self._get_fd_part(syscall.param('in_fd'), self._mode)
        elif 'out_fd' in params:
            return self._get_fd_part(syscall.param('in_fd'), self._mode)
        else:
            return None

    @staticmethod
    def _get_fd_part(fd, mode: FDMode):
        fd_parts = fd[:-1].split('(')
        part = fd_parts[mode]
        pattern = r'<.*>'
        if '->' in part:
            return tuple(re.sub(pattern, '', e) for e in part.split('->'))
        else:
            return tuple([re.sub(pattern, '', part)])

    def depends_on(self):
        return []
