from typing import Optional

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.filedescriptor import FileDescriptor, FDMode
from dataloader.syscall import Syscall


class PathLikeParam(BuildingBlock):
    """
    Returns the first parameter that exists given a list of possible parameters.
    Path like parameters can be:
        - fd
        - in_fd
        - out_fd
        - path
        - name
        - oldpath
        - newpath
        - filename
        - exe
    This is a very simple implementation, it does not check if the parameter is a path.
    """

    def __init__(self, params: list[str]):
        super().__init__()
        self._params = params

    def _calculate(self, syscall: Syscall) -> Optional[tuple]:
        for param in self._params:
            path = syscall.param(param)
            if path is not None:
                if param in ["fd", "in_fd", "out_fd"]:
                    if "<f>" in path:
                        result = FileDescriptor.get_fd_part(path, FDMode.Content)
                        return result
                else:
                    return path,

    def depends_on(self) -> list:
        return []
