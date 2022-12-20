from dataloader.syscall import Syscall
from typing import Optional
from algorithms.building_block import BuildingBlock

MIN = 0
MAX = 1


class AABB(BuildingBlock):
    def __init__(self,
                 feature: BuildingBlock):
        """
        Building Block that implements the axis alignes bounding box (aabb) decider approach

        Idea: find min and max for all dimensions of feature input from validation data
        all min and max values create an n-dimensional bounding box where n is the number of dimensions

        if a new input vector is inside the bounding box the data point is considered benign
        if it is not inside the bounding box it is considered an anomaly
        @param feature: the input feature building block
        """
        super().__init__()
        self._feature = feature
        self._dependency_list = []
        self._dependency_list.append(self._feature)

        self.min_max_values = []

        self._cache = {}

    def depends_on(self):
        return self._dependency_list

    def val_on(self, syscall: Syscall):
        """
        stores the min and max value for every dimension of the input space in a 2-dimensional list

        @param syscall: the syscall object to evaluate
        """
        feature_input = self._convert_to_tuple(self._feature.get_result(syscall))

        if feature_input is not None:
            for dimension, value in enumerate(feature_input):
                if len(self.min_max_values) < len(feature_input):
                    self.min_max_values.append([value, value])

                if value < self.min_max_values[dimension][MIN]:
                    self.min_max_values[dimension][MIN] = value

                if value > self.min_max_values[dimension][MAX]:
                    self.min_max_values[dimension][MAX] = value

    def _calculate(self, syscall: Syscall) -> Optional[bool]:
        """
        return True if all values of all dimensions are in min max range of their features
        else return false
        @param syscall: the syscall object to evaluate
        """
        feature_input = self._convert_to_tuple(self._feature.get_result(syscall))

        if feature_input is not None:
            # caching the result
            if feature_input in self._cache.keys():
                return self._cache[feature_input]
            else:
                decider_state = False
                for dimension, value in enumerate(feature_input):
                    if value < self.min_max_values[dimension][MIN]:
                        decider_state = True
                        break
                    if value > self.min_max_values[dimension][MAX]:
                        decider_state = True
                        break
                self._cache[tuple(feature_input)] = decider_state
                return decider_state
        else:
            return None

    @staticmethod
    def _convert_to_tuple(feature_input) -> Optional[tuple]:
        """
        checks type of feature input and creates a tuple out of it if input is 1-dim
        @param feature_input:
        @return: checked input

        """
        if feature_input is None:
            return None
        elif type(feature_input) == int or type(feature_input) == float:
            # if input is not a tuple create a 1-dimensional tuple containing the int or float input
            feature_input = (feature_input,)
        elif type(feature_input) == tuple:
            pass
        else:
            raise ValueError("AABB input feature needs to be int, float or tuple")
        return feature_input

    def is_decider(self):
        return True
