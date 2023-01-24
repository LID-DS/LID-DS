import re
from enum import IntEnum

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class FDMode(IntEnum):
    """
        modes for FileDescriptor Extraction
    """
    ID = 0
    Content = 1


class FileDescriptor(BuildingBlock):
    """
        extracts filedescriptor contents from system call line
        2 Modes:
            ID: get fd ID
            Content: get fd Content (IPs, filepaths...)
        if more than one fd is present a tuple containing all contents is returned
        always starts with in_fd then out_fd
        IP address pairs with direction are extracted together like:
            ('172.17.0.1:45440->172.17.0.5:8080', )

        args:
            mode: the extraction mode of the BuildingBlock, see FDMode class
    """

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
        # check which kind of file_descriptor exists
        if 'fd' in params:
            return self.get_fd_part(syscall.param('fd'), self._mode)
        # in_fd can occur without out_fd
        elif 'in_fd' in params:
            if 'out_fd' in params:
                return self.get_fd_part(syscall.param('in_fd'), self._mode) + self.get_fd_part(
                    syscall.param('out_fd'), self._mode)
            else:
                return self.get_fd_part(syscall.param('in_fd'), self._mode)
        # catch only out_fd
        elif 'out_fd' in params:
            return self.get_fd_part(syscall.param('out_fd'), self._mode)
        # no fd in syscall
        else:
            return None

    @staticmethod
    def get_fd_part(fd, mode: FDMode):
        """
            split fd content into its parts and return it according to extraction mode
            cast to tuples

            args:
                mode: the extraction mode of the BuildingBlock, see FDMode class
        """
        # some fds are only ints, checked by looking for braces
        if '(' in fd:
            fd_parts = fd[:-1].split('(')
            part = fd_parts[mode]
            pattern = r'<.{,5}>'
            # check if content is integer
            try:
                return tuple([int(re.sub(pattern, '', part))])
            except ValueError:
                fd_tuple = tuple([re.sub(pattern, '', part)])
                # check if content is empty
                if len(fd_tuple[0]) == 0:
                    return None
                else:
                    return fd_tuple
        else:
            if mode == FDMode.ID:
                return (int(fd), )
            else:
                return None

    def depends_on(self):
        return []
