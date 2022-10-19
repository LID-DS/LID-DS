"""
Building Block for combination of two threshold BBs
"""
from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock


class AndDecider(BuildingBlock):
    """
        Returns 1 if both deciders return 1.
    """

    def __init__(self,
                 decider_list: list):
        super().__init__()

        self._dependency_list = []
        for feature in decider_list:
            if feature.is_decider():
                self._dependency_list.append(feature)
            else:
                raise ValueError('Combination Threshold: At least one feature is not a decider')

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        Return 1 if both deciders return 1
        Otherwise return 0.
        """
        return_decision = True
        for decider in self._dependency_list:
            decision = decider.get_result(syscall)
            if decision is False:
                return_decision = False
        return return_decision

    def is_decider(self):
        return True
