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

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        calculates the maximum from the dependecy list
        """
        result = None
        for bb in self._dependency_list:
            if bb.get_id() in dependencies and dependencies[bb.get_id()] is not None:
                bb_value = dependencies[bb.get_id()]                
                if result is None or bb_value > result:
                    result = bb_value
        if result is not None:
            dependencies[self.get_id()] = result

