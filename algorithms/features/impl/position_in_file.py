from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class PositionInFile(BuildingBlock):
    """
    returns the line of the current system call
    """

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        returns the line_id (line number regarding the file of the system call)
        """        
        return syscall.line_id

    def depends_on(self):
        return []
