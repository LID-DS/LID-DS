from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock

MIN = 0
MAX = 1


class AABB(BuildingBlock):
    def __init__(self,
                 feature: BuildingBlock):
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
        feature_input = self._check_input_type(self._feature.get_result(syscall))

        if feature_input is not None:
            for dimension, value in enumerate(feature_input):
                if len(self.min_max_values) < len(feature_input):
                    self.min_max_values.append([value, value])

                if value < self.min_max_values[dimension][MIN]:
                    self.min_max_values[dimension][MIN] = value

                if value > self.min_max_values[dimension][MAX]:
                    self.min_max_values[dimension][MAX] = value

    def _calculate(self, syscall: Syscall) -> bool:
        """
        return True if all values of all dimensions are in min max range of their features
        else return false
        @param syscall: the syscall object to evaluate
        """
        feature_input = self._check_input_type(self._feature.get_result(syscall))

        if feature_input is not None:
            # caching the result
            if tuple(feature_input) in self._cache.keys():
                return self._cache[tuple(feature_input)]
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
    def _check_input_type(feature_input):
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
