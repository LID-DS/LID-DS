import math
from collections import Counter

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class Entropy(BuildingBlock):
    """
        Calculates entropy of given BuildingBlock.
        Default entropy is shannon entropy (Base 2).
        If BuildingBlock is None 0 is returned.
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
            defined in self._feature
            Params:
            syscall(Syscall): syscall to calc entropy of
        """
        value = self._feature.get_result(syscall)
        if type(value) == int:
            # every digit as list entry
            res = [value]
        elif type(value) == str:
            res = list(value)
        elif type(value) == tuple:
            res = list(value)
        elif value is None:
            return None
        else:
            print('''Sadly this feature is only implemented for:
                  str, int and tuple.''')
            raise ValueError
        entropy = self._calc_entropy(res)

        return entropy

    def _calc_entropy(self,
                      label: list,
                      unit: str = 'shannon'):
        """
            Computes entropy of label distribution.
            Label can be list of variable entries thanks to Counter.
            Base is set to 2 through unit -> Shannon entropy
            Params:
            label: list of labels
            Returns:
            float: entropy value
        """
        base = {
             'shannon': 2.,
             'natural': math.exp(1),
             'hartley': 10.
        }
        if len(label) <= 1:
            return 0

        counts = Counter()

        for d in label:
            counts[d] += 1

        ent = 0

        probs = [float(c) / len(label) for c in counts.values()]
        for p in probs:
            if p > 0.:
                ent -= p * math.log(p, base[unit])
        return ent
