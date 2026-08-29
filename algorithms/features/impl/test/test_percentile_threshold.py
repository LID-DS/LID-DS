import numpy as np
import pytest

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.percentile_threshold import PercentileThreshold
from dataloader.syscall_2021 import Syscall2021


class _ScoreStub(BuildingBlock):
    """Returns a fixed sequence of anomaly scores, one per syscall;
    after exhaustion it returns `probe` (for classification checks)."""

    def __init__(self, scores, probe=None):
        super().__init__()
        self._scores = list(scores)
        self._probe = probe
        self._i = 0

    def depends_on(self):
        return []

    def _calculate(self, syscall):
        if self._i < len(self._scores):
            value = self._scores[self._i]
            self._i += 1
            return value
        return self._probe


def _sc(idx=0):
    return Syscall2021('test/rec.zip',
                       f"100000000{idx} 0 1 proc 1 open < res=0")


def test_percentile_threshold_sets_percentile_of_validation_scores():
    scores = list(range(1, 101))  # 1..100
    stub = _ScoreStub(scores)
    pt = PercentileThreshold(stub, percentile=99)

    syscalls = [_sc(idx=i) for i in range(len(scores))]

    # Validation phase: collect scores
    for sc in syscalls:
        pt.val_on(sc)
    pt.fit()

    expected = float(np.percentile(scores, 99))
    assert pt._threshold == pytest.approx(expected)


def test_percentile_threshold_classifies_against_learned_threshold():
    scores = list(range(1, 101))
    stub = _ScoreStub(scores)
    pt = PercentileThreshold(stub, percentile=99)

    syscalls = [_sc(idx=i) for i in range(len(scores))]
    for sc in syscalls:
        pt.val_on(sc)
    pt.fit()

    # After fitting, a score above the 99th percentile (99.01) is an alarm,
    # a score below is not (probe values served after the score sequence)
    above = _ScoreStub(list(range(1, 101)), probe=100.0)
    pt_above = PercentileThreshold(above, percentile=99)
    for sc in syscalls:
        pt_above.val_on(sc)
    pt_above.fit()
    # the stub returns 100.0 once, then None; the first calculate call gets 100.0
    assert pt_above._calculate(_sc(idx=2000)) is True

    below = _ScoreStub(list(range(1, 101)), probe=99.0)
    pt_below = PercentileThreshold(below, percentile=99)
    for sc in syscalls:
        pt_below.val_on(sc)
    pt_below.fit()
    assert pt_below._calculate(_sc(idx=3000)) is False


def test_percentile_threshold_is_decider():
    stub = _ScoreStub([1.0, 2.0])
    pt = PercentileThreshold(stub, percentile=99.5)
    assert pt.is_decider() is True


def test_percentile_threshold_default_percentile():
    stub = _ScoreStub([1.0, 2.0])
    pt = PercentileThreshold(stub)
    assert pt._percentile == 99.5
