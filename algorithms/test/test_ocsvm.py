import pytest

from algorithms.decision_engines.ocsvm import OCSVM
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from dataloader.syscall_2021 import Syscall2021


def _sc(name, tid=1, idx=0):
    return Syscall2021('test/rec.zip',
                       f"100000000{idx} 0 {tid} proc 1 {name} < res=0")


def _build_ocsvm_pipeline(ngram_length=3):
    ie = IntEmbedding()
    ngram = Ngram(feature_list=[ie],
                  thread_aware=False,
                  ngram_length=ngram_length)
    ocsvm = OCSVM(ngram, kernel='rbf', nu=0.5)
    return ie, ngram, ocsvm


def test_ocsvm_trains_and_scores():
    """OCSVM should train on distinct n-grams and produce finite anomaly scores."""
    ie, ngram, ocsvm = _build_ocsvm_pipeline(ngram_length=3)

    # Normal behavior: repeating open, close, read sequence
    names = ['open', 'close', 'read'] * 4
    training_syscalls = [_sc(name, idx=i) for i, name in enumerate(names)]

    for sc in training_syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in training_syscalls:
        ocsvm.train_on(sc)
    ocsvm.fit()

    # Score the same normal sequence
    ngram.new_recording()
    normal_scores = [ocsvm.get_result(sc) for sc in training_syscalls]
    normal_scores = [s for s in normal_scores if s is not None]
    assert len(normal_scores) > 0
    for s in normal_scores:
        assert isinstance(s, float)
        assert s == s  # not NaN

    # Anomalous sequence: unknown syscall name (int 0 in the n-gram)
    anomaly_syscalls = [_sc('open', idx=100), _sc('close', idx=101), _sc('totally_unknown', idx=102)]
    ngram.new_recording()
    anomaly_scores = [ocsvm.get_result(sc) for sc in anomaly_syscalls]
    anomaly_scores = [s for s in anomaly_scores if s is not None]
    assert len(anomaly_scores) > 0
    for s in anomaly_scores:
        assert isinstance(s, float)


def test_ocsvm_scores_unknown_ngram_as_anomalous():
    """An n-gram containing an unseen syscall should not score below all normal n-grams."""
    ie, ngram, ocsvm = _build_ocsvm_pipeline(ngram_length=3)

    names = ['open', 'close', 'read'] * 4
    training_syscalls = [_sc(name, idx=i) for i, name in enumerate(names)]

    for sc in training_syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in training_syscalls:
        ocsvm.train_on(sc)
    ocsvm.fit()

    ngram.new_recording()
    normal_scores = [ocsvm.get_result(sc) for sc in training_syscalls]
    normal_scores = [s for s in normal_scores if s is not None]

    anomaly_syscalls = [_sc('open', idx=100), _sc('close', idx=101), _sc('totally_unknown', idx=102)]
    ngram.new_recording()
    anomaly_scores = [ocsvm.get_result(sc) for sc in anomaly_syscalls]
    anomaly_scores = [s for s in anomaly_scores if s is not None]

    # The unseen n-gram should score at least as anomalous as the least
    # anomalous normal n-gram (OCSVM: higher score = more anomalous).
    assert max(anomaly_scores) >= min(normal_scores)


def test_ocsvm_result_cache_returns_consistent_scores():
    """Repeated scoring of the same n-gram should yield the same (cached) score."""
    ie, ngram, ocsvm = _build_ocsvm_pipeline(ngram_length=3)

    names = ['open', 'close', 'read'] * 4
    training_syscalls = [_sc(name, idx=i) for i, name in enumerate(names)]

    for sc in training_syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in training_syscalls:
        ocsvm.train_on(sc)
    ocsvm.fit()

    ngram.new_recording()
    first = [ocsvm.get_result(sc) for sc in training_syscalls]
    ngram.new_recording()
    second = [ocsvm.get_result(sc) for sc in training_syscalls]
    assert first == second
