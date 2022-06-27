from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Flags(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate flag parameter from syscall
        eg: flags=65(O_NONBLOCK|O_RDONLY)
            flags=0
        """
        params = syscall.params()
        if "flags" in params:
            return params["flags"]
        else:
            return "0"

    def depends_on(self):
        return []
