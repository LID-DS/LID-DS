from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Mode(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        """
        calculate mode parameter from syscall
        eg: mode=0
        """
        params = syscall.params()
        if "mode" in params:
            return params["mode"]
        else:
            return "0"        

    def depends_on(self):
        return []
