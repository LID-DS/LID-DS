"""
Building Block for max value of training threshold.
"""
from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock


class MaxScoreThreshold(BuildingBlock):
    """
        Saves maximum anomaly score of validation data as threshold.
    """

    def __init__(self,
                 feature: BuildingBlock):
        super().__init__()
        self._threshold = 0

        self._feature = feature
        self._dependency_list = []
        self._dependency_list.append(self._feature)

    def depends_on(self):
        return self._dependency_list

    def val_on(self, syscall: Syscall):
        """
        save highest seen anomaly_score
        """
        anomaly_score = self._feature.get_result(syscall)
        if isinstance(anomaly_score, (int, float)):
            if anomaly_score > self._threshold:
                self._threshold = anomaly_score

    def _calculate(self, syscall: Syscall) -> bool:
        """
        Return 0 if anomaly_score is below threshold.
        Otherwise return 1.
        """
        anomaly_score = self._feature.get_result(syscall)
        if isinstance(anomaly_score, (int, float)):
            if anomaly_score > self._threshold:
                return True
        return False

    def is_decider(self):
        return True
