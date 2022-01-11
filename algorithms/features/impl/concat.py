import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class Concat(BuildingBlock):
    """
    concats the given bbs in the given order to a new value
    """

    def __init__(self, bbs_to_concat: list):
        """
        """
        super().__init__()

        self._dependency_list = []
        self._dependency_list.extend(bbs_to_concat)        

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        concats the given bbs in the given order to a new value
        """
        result_vector = []
        for bb in self._dependency_list:
            if bb.get_id() in dependencies and dependencies[bb.get_id()] is not None:
                bb_value = dependencies[bb.get_id()]
                if isinstance(bb_value, str):
                    result_vector.append(bb_value)
                else:
                    try:
                        result_vector.extend(bb_value)
                    except TypeError:
                        result_vector.append(bb_value)
            else:
                return
        dependencies[self.get_id()] = tuple(result_vector)

