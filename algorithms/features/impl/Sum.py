import math
from collections import deque

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Sum(BuildingBlock):
    """
    calculates the sum from the given bbs
    if the input BBs are scalar values the result is a scalar
    if the input BBs are tuples with dimension D, the result is a tuple with dimension D, each dimension is summed seperately
    """

    def __init__(self, bbs_to_concider: list):
        """
        """
        super().__init__()

        self._dependency_list = []
        self._dependency_list.extend(bbs_to_concider)
        self._result_length = None

    def depends_on(self):
        return self._dependency_list

    def val_on(self, syscall: Syscall):
        """
        used to determine the size of the input bbs
        """
        lengths = []        
        for bb in self._dependency_list:
            bb_value = bb.get_result(syscall)
            if bb_value is not None:                
                if isinstance(bb_value, tuple):
                    new_length = len(bb_value)
                else:
                    new_length = 1
                lengths.append(new_length)

                if self._result_length is None:
                    self._result_length = new_length
                elif self._result_length != new_length:                    
                    raise ValueError(f"inputs to {self.__str__()} are of different lengths: {lengths}")
            else:
                lengths.append(None)
    
    def _calculate(self, syscall: Syscall):
        """
        calculates the sum from the dependecy list
        """
        check = True
        result = None            
        for bb in self._dependency_list:
            bb_value = bb.get_result(syscall)
            if bb_value is not None:
                # bb_value is not None
                if self._result_length == 1:
                    # scalar
                    if result is None:
                        result = bb_value
                    elif result is not None:
                        result += bb_value
                else:
                    # vector (tuple)
                    if result is None:
                        result = list(bb_value)
                    else:
                        for i in range(len(bb_value)):
                            result[i] += bb_value[i]
            else:
                # bb_value is None
                check = False

        if result is not None and check:
            if self._result_length > 1:
                return tuple(result)
            else:
                return result
        else:
            return None

