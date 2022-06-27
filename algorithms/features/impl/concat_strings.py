import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class ConcatStrings(BuildingBlock):
    """
    concats the given bbs (strings) in the given order to a new value (string)
    """

    def __init__(self, bb: BuildingBlock):
        """
        """
        super().__init__()

        self._bb = bb
        self._dependency_list = [bb]        

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        if dependency is not None:
            returns the elements of the given bb as String in the given order
        otherwise:
            returns None
        """
        result_str = ""
        error = False        
        tmp_input = self._bb.get_result(syscall)
        if tmp_input is not None:                
            for element in tmp_input:                
                if isinstance(element, str):                    
                    result_str += element
                else:
                    result_str += str(element)
            return result_str
        else:
            return None


