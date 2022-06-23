from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Timestamp(BuildingBlock):
    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        return syscall.timestamp_unix_in_ns()

    def depends_on(self):
        return []
