from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class Flags(BuildingBlock, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def calculate(self, syscall: Syscall, features: dict):
        """
        calculate flag parameter from syscall
        eg: flags=65(O_NONBLOCK|O_RDONLY)
            flags=0
        """
        params = syscall.params()
        if "flags" in params:
            features[self.get_id()] = params["flags"]
        else:
            features[self.get_id()] = "0"

    def depends_on(self):
        return []
