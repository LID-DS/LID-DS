"""
Building Block for percentile-based threshold on validation scores.
"""
import numpy as np

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class PercentileThreshold(BuildingBlock):
    """
    Saves a percentile of validation anomaly scores as threshold.
    Unlike MaxScoreThreshold (which uses the absolute max and thus
    guarantees zero validation false positives), this allows a small
    fraction of validation scores to exceed the threshold, trading
    fewer false negatives for slightly more false positives.
    """

    def __init__(self, feature: BuildingBlock, percentile: float = 99.5):
        super().__init__()
        self._feature = feature
        self._percentile = percentile
        self._threshold = 0.0
        self._val_scores = []
        self._dependency_list = [self._feature]

    def depends_on(self):
        return self._dependency_list

    def val_on(self, syscall: Syscall):
        anomaly_score = self._feature.get_result(syscall)
        if isinstance(anomaly_score, (int, float)):
            self._val_scores.append(anomaly_score)

    def fit(self):
        if self._val_scores:
            self._threshold = float(np.percentile(self._val_scores, self._percentile))
            print(f"threshold(p{self._percentile})={self._threshold:.6f}".rjust(27))
        self._val_scores = []

    def _calculate(self, syscall: Syscall) -> bool:
        anomaly_score = self._feature.get_result(syscall)
        if isinstance(anomaly_score, (int, float)):
            if anomaly_score > self._threshold:
                return True
        return False

    def is_decider(self):
        return True
