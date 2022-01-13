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

    def _calculate(self, syscall: Syscall):
        """
        concats the given bbs in the given order to a new value
        """
        result_vector = []
        for bb in self._dependency_list:
            tmp_input = bb.get_result(syscall)
            if tmp_input is not None:                
                if isinstance(tmp_input, str):
                    result_vector.append(tmp_input)
                else:
                    try:
                        result_vector.extend(tmp_input)
                    except TypeError:
                        result_vector.append(tmp_input)
            else:
                return None
        return tuple(result_vector)

