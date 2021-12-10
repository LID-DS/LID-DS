from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class Mode(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def calculate(self, syscall: Syscall, features: dict):
        """
        calculate mode parameter from syscall
        eg: mode=0
        """
        params = syscall.params()
        if "mode" in params:
            features[self.get_id()] = params["mode"]
        else:
            features[self.get_id()] = "0"

    def depends_on(self):
        return []
