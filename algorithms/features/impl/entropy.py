import math
import numpy as np
from collections import deque


from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Entropy(BuildingBlock):
    """
    calculates entropy of give BuildingBlock
    """

    def __init__(self, feature: BuildingBlock):
        """
        feature: entropy is calculated on feature
        """
        super().__init__()

        self._dependency_list = []
        self._dependency_list.append(feature)
        self._feature = feature

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        calculates the entropy of result of BuildingBlock 
        """
        value = self._feature.get_result(syscall)
        if type(value) == int:
            # every digit as list entry
            res = [int(x) for x in str(value)]
            entropy = self._calc_entropy(res)
        else: 
            raise ValueError  

        return entropy 

    def _calc_entropy(self, labels: list):
        """
            calculates entropy of given labels
        """
        value,counts = np.unique(labels, return_counts=True)
        norm_counts = counts / counts.sum()
        base = e if base is None else base
        return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()
