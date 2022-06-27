import typing
import numpy as np

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class PositionalEncoding(BuildingBlock):
    """
        convert a number to an n dimensional vector using positional encoding from Attention is all you need (http://papers.nips.cc/paper/7181-attention-is-all-you-%0Aneed.pdf)
    """

    def __init__(self, number: BuildingBlock, n: int):
        super().__init__()
        self._number = number
        self._dimensions = n
        self._dependencies = [self._number]
        
    def depends_on(self):
        return self._dependencies

    def _calculate(self, syscall: Syscall):
        """
            transforms given number to pos. encoding
        """        
        number = self._number.get_result(syscall)
        if number is not None:
            return PositionalEncoding._pe(number,self._dimensions)
        else:
            return None
        
        

    def _pe(position, dimensions):                        
        pe = np.array([position / np.power(10000, 2 * (i // 2) / dimensions) for i in range(dimensions)])
        #print(pe)
        pe[0::2] = np.sin(pe[0::2])  # dim 2i
        pe[1::2] = np.cos(pe[1::2])  # dim 2i+1
        #print(pe)
        return tuple(pe)
