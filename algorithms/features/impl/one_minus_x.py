
from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class OneMinusX(BuildingBlock):
    """
    calculates 1 - x (value of BB)
    """

    def __init__(self, x: BuildingBlock):
        super().__init__()
        self._dependency_list = []
        self._dependency_list.append(x)
        self._x = x        

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        Returns:
            nothing if no x exists
            1 - x otherwise
        """
        x_value = self._x.get_result(syscall)
        if x_value is not None:
                return 1.0 - x_value
        else:
            return None
