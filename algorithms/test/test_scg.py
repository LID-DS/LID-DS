import math

import pytest

from algorithms.decision_engines.scg import SystemCallGraph
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.select import Select
from dataloader.syscall_2021 import Syscall2021


def _sc(name, idx=0):
    """Create a Syscall2021 with given syscall name."""
    return Syscall2021('test/rec.zip', f"100000000{idx} 0 1 proc 1 {name} < res=0")


def _build_trained_scg(scoring_mode='probability', confidence_tau=10.0):
    """
    Build and train SCG on: open, close, read, open, close.

    Graph edges:
        (1,)->(2,) f=2, p=1.0
        (2,)->(3,) f=1, p=1.0
        (3,)->(1,) f=1, p=1.0
    max_f = 2
    """
    ie = IntEmbedding()
    ie._syscall_dict = {}
    ngram = Ngram([ie], thread_aware=False, ngram_length=1)
    scg = SystemCallGraph(ngram, thread_aware=False,
                          scoring_mode=scoring_mode, confidence_tau=confidence_tau)

    training = [_sc('open', 0), _sc('close', 1), _sc('read', 2), _sc('open', 3), _sc('close', 4)]
    for sc in training:
        ie.train_on(sc)
        ngram.train_on(sc)
        scg.train_on(sc)

    ie.fit()
    ngram.fit()
    scg.fit()

    scg.new_recording()
    ngram.new_recording()

    return scg


def test_probability_mode():
    scg = _build_trained_scg('probability')
    sc1, sc2, sc3 = _sc('open', 10), _sc('close', 11), _sc('write', 12)

    assert scg.get_result(sc1) is None        # first syscall
    assert scg.get_result(sc2) == 0.0          # (1,)->(2,) p=1.0
    assert scg.get_result(sc3) == 1.0          # unknown edge


def test_frequency_mode():
    scg = _build_trained_scg('frequency')
    sc1, sc2, sc3, sc4 = _sc('open', 10), _sc('close', 11), _sc('read', 12), _sc('write', 13)

    assert scg.get_result(sc1) is None
    assert scg.get_result(sc2) == 0.0          # f=2, max_f=2 -> 1-1.0=0.0
    assert scg.get_result(sc3) == 0.5          # f=1, max_f=2 -> 1-0.5=0.5
    assert scg.get_result(sc4) == 1.0          # unknown


def test_confidence_mode():
    scg = _build_trained_scg('confidence', confidence_tau=1.0)
    sc1, sc2, sc3 = _sc('open', 10), _sc('close', 11), _sc('write', 12)

    assert scg.get_result(sc1) is None
    # (1,)->(2,): f=2, p=1.0, conf = 1-exp(-2/1), score = 1 - conf * 1.0
    expected = 1.0 - (1.0 - math.exp(-2.0)) * 1.0
    assert abs(scg.get_result(sc2) - expected) < 1e-10
    # unknown: score = 1.0
    assert scg.get_result(sc3) == 1.0


def test_2tuple_mode():
    scg = _build_trained_scg('2-tuple')
    sc1, sc2, sc3 = _sc('open', 10), _sc('close', 11), _sc('write', 12)

    assert scg.get_result(sc1) is None
    assert scg.get_result(sc2) == (0.0, 0.0)  # known, max freq
    assert scg.get_result(sc3) == (1.0, 1.0)  # unknown


def test_3tuple_mode():
    scg = _build_trained_scg('3-tuple', confidence_tau=1.0)
    sc1, sc2 = _sc('open', 10), _sc('close', 11)

    assert scg.get_result(sc1) is None
    result = scg.get_result(sc2)
    assert len(result) == 3
    assert result[0] == 0.0   # prob score
    assert result[1] == 0.0   # freq score
    expected_conf = 1.0 - (1.0 - math.exp(-2.0)) * 1.0
    assert abs(result[2] - expected_conf) < 1e-10


def test_select_index_with_tuple():
    scg = _build_trained_scg('2-tuple')
    sel0 = Select(scg, index=0)
    sel1 = Select(scg, index=1)

    sc1, sc2 = _sc('open', 10), _sc('close', 11)

    assert sel0.get_result(sc1) is None
    assert sel1.get_result(sc1) is None
    assert sel0.get_result(sc2) == 0.0   # probability score
    assert sel1.get_result(sc2) == 0.0   # frequency score


def test_select_index_validation():
    ie = IntEmbedding()
    with pytest.raises(ValueError):
        Select(ie, start=0, end=1, index=0)
    with pytest.raises(ValueError):
        Select(ie)


def test_invalid_scoring_mode():
    ie = IntEmbedding()
    ngram = Ngram([ie], thread_aware=False, ngram_length=1)
    with pytest.raises(ValueError):
        SystemCallGraph(ngram, scoring_mode='invalid')
