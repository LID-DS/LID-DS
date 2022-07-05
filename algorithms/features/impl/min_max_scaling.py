import math
import typing

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class MinMaxScaling(BuildingBlock):
    def __init__(self, bb_to_scale: BuildingBlock):
        """
        """
        super().__init__()
        self._min = math.inf
        self._max = -math.inf
        self._bb_to_scale = bb_to_scale
        self._bb_id = self._bb_to_scale.get_id()
        self._diff = 0

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        return [self._bb_to_scale]

    def train_on(self, syscall: Syscall):
        current_value = self._bb_to_scale.get_result(syscall)
        if current_value is not None:
            if current_value < self._min:
                self._min = current_value
            if current_value > self._max:
                self._max = current_value                

    def val_on(self, syscall: Syscall):
        current_value = self._bb_to_scale.get_result(syscall)
        if current_value is not None:
            if current_value < self._min:
                self._min = current_value
            if current_value > self._max:
                self._max = current_value

    def fit(self):
        self._diff = self._max - self._min
        if self._diff == 0:
            print(f"cant calculate MinMaxScaling for {self._bb_to_scale} - instead calculating identity function")

    def _calculate(self, syscall: Syscall):
        """
        """
        current_value = self._bb_to_scale.get_result(syscall)
        if current_value is not None:
            if self._diff != 0:
                return (current_value - self._min) / self._diff
            else:
                return current_value
        else:
            return None
