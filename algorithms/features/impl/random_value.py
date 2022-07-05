from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall

from random import seed
from random import random
seed(1)

class RandomValue(BuildingBlock):

    def __init__(self, size=1, scale=1.0):
        """
        generates random values between -1.0 and 1.0 multiplied by scale
        if size == 1: generates a scalar value
        if size > 1: generates a tuple of size with random values
        """
        super().__init__()
        self._size = size        
        self._a = -scale
        self._b = 2.0 * scale

    def _calculate(self, syscall: Syscall):
        if self._size == 1:
            return self._a + (random() * self._b)
        else:
            values = [self._a + (random() * self._b) for _ in range(self._size)]            
            return tuple(values)

    def depends_on(self):
        return []

