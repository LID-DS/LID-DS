import math
from collections import deque

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Maximum(BuildingBlock):
    """
    calculates the maximum from the given bbs
    """

    def __init__(self, bbs_to_concider: list):
        """
        """
        super().__init__()

        self._dependency_list = []
        self._dependency_list.extend(bbs_to_concider)

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        calculates the maximum from the dependecy list
        """
        result = None
        check = True
        for bb in self._dependency_list:
            bb_value = bb.get_result(syscall)
            if bb_value is not None:
                if result is None or bb_value > result:
                    result = bb_value
            else:
                check = False
        if result is not None and check:
            return result
        else:
            return None

