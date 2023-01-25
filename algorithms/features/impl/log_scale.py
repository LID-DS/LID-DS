from math import log

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class LogScale(BuildingBlock):
    """
    Logarithmic scaling of a feature
    """

    def __init__(self, feature: BuildingBlock, base: int, linear_interpolation_value: int):
        """
        Scale a feature logarithmically if it is above a certain value and is an int or float

        Args:
            feature: input feature
            base:  base of the logarithm
            linear_interpolation_value: value below which the feature is not scaled
        """
        super().__init__()
        self._feature = feature
        self._base = base
        self._dependency_list = [feature]
        if linear_interpolation_value is None:
            self._linear_interpolation_value = 0
        else:
            self._linear_interpolation_value = linear_interpolation_value

    def _calculate(self, syscall: Syscall):
        feature_result = self._feature.get_result(syscall)
        if feature_result is None:
            return None
        if not isinstance(feature_result, int) and not isinstance(feature_result, float):
            return feature_result
        if feature_result <= self._linear_interpolation_value:
            return feature_result
        return log(feature_result, self._base)

    def depends_on(self) -> list:
        return self._dependency_list
