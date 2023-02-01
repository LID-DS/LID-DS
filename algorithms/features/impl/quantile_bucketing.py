from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall
import numpy as np


class QuantileBucketing(BuildingBlock):
    """
        Distribute a feature's values into buckets (in order) so that each bucket contains the same (or almost the same) number of examples.
        Returns the bucket index of the feature value.
    """

    def __init__(self, input_feature: BuildingBlock, num_buckets: int, excluded_values: list = None):
        """

        Args:
            num_buckets (int): number of buckets
            excluded_values: values that should not be considered for bucketing (can be used for values with special meaning)
        """
        super().__init__()
        self._input_feature = input_feature
        self._num_buckets = num_buckets
        self._bucket_boundaries = None
        self._dependency_list = [input_feature]
        self._values = []
        self._max_value = 0
        if excluded_values is None:
            self._excluded_values = set()
        else:
            self._excluded_values = set(excluded_values)

    def train_on(self, syscall: Syscall):
        value = self._input_feature.get_result(syscall)
        if not isinstance(value, (int, float)) or value in self._excluded_values:
            return
        if value > self._max_value:
            self._max_value = value
        self._values.append(value)

    def fit(self):
        if self._bucket_boundaries is not None:
            self._values = []
            return
        quantiles = np.quantile(self._values, np.arange(0, 1, 1 / self._num_buckets))
        self._bucket_boundaries = list(dict.fromkeys(quantiles))
        self._bucket_boundaries.append(self._max_value)
        self._values = []

    def _calculate(self, syscall: Syscall):
        value = self._input_feature.get_result(syscall)
        if value is None:
            return None
        if not isinstance(value, (int, float)) or value in self._excluded_values:
            # TODO: this might be a problem, if value > len(excluded_values)
            return value
        for i, boundary in enumerate(self._bucket_boundaries[1:], start=len(self._excluded_values)):
            if value <= boundary:
                return i
        return len(self._excluded_values) + len(self._bucket_boundaries)

    def depends_on(self) -> list:
        return self._dependency_list
