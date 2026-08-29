import torch
import pytest

from algorithms.decision_engines.cnn import CNN
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.select import Select
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from dataloader.syscall_2021 import Syscall2021


def _sc(name, tid=1, idx=0):
    return Syscall2021('test/rec.zip',
                       f"100000000{idx} 0 {tid} proc 1 {name} < res=0")


def _build_cnn_pipeline(ngram_length=3):
    """Build a minimal CNN pipeline: IntEmb -> OHE -> Ngram(n+1) -> Select + OHE -> CNN."""
    torch.manual_seed(42)

    ie = IntEmbedding()
    ohe = OneHotEncoding(ie)

    ngram = Ngram(feature_list=[ohe],
                  thread_aware=False,
                  ngram_length=ngram_length + 1)

    n = ngram_length
    select_input = Select(ngram, start=0,
                          end=lambda: n * ohe.get_embedding_size())
    select_label = Select(ngram, start=lambda: n * ohe.get_embedding_size())

    cnn = CNN(input_vector=select_input,
              output_label=select_label,
              input_channels=n,
              num_filters=16,
              num_conv_layers=1,
              kernel_size=3,
              batch_size=4,
              learning_rate=0.003)

    return ie, ohe, ngram, select_input, select_label, cnn


def test_cnn_basic_pipeline():
    """CNN should train and produce anomaly scores."""
    ie, ohe, ngram, sel_in, sel_label, cnn = _build_cnn_pipeline(ngram_length=3)

    # Sequence: open, close, read, write, open, close, read, write, open, close
    syscalls_names = ['open', 'close', 'read', 'write'] * 3
    training_syscalls = [_sc(name, idx=i) for i, name in enumerate(syscalls_names)]

    # Train
    for sc in training_syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in training_syscalls:
        ohe.train_on(sc)
    ohe.fit()

    for sc in training_syscalls:
        ngram.train_on(sc)
        sel_in.train_on(sc)
        sel_label.train_on(sc)
        cnn.train_on(sc)

    ngram.fit()
    sel_in.fit()
    sel_label.fit()

    # Validate (use same data for test simplicity)
    ngram.new_recording()
    for sc in training_syscalls:
        cnn.val_on(sc)

    cnn.fit()

    # Test: produce scores
    ngram.new_recording()
    scores = []
    for sc in training_syscalls:
        result = cnn.get_result(sc)
        if result is not None:
            scores.append(result)

    # Should have produced some scores
    assert len(scores) > 0
    # Scores should be in [0, 1]
    for s in scores:
        assert 0.0 <= s <= 1.0, f"Score {s} out of range"


def test_cnn_returns_none_until_ngram_full():
    """CNN should return None until the ngram buffer fills."""
    ie, ohe, ngram, sel_in, sel_label, cnn = _build_cnn_pipeline(ngram_length=3)

    syscalls_names = ['open', 'close', 'read', 'write'] * 3
    training_syscalls = [_sc(name, idx=i) for i, name in enumerate(syscalls_names)]

    for sc in training_syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in training_syscalls:
        ohe.train_on(sc)
    ohe.fit()
    for sc in training_syscalls:
        ngram.train_on(sc)
        sel_in.train_on(sc)
        sel_label.train_on(sc)
        cnn.train_on(sc)
    ngram.fit()
    sel_in.fit()
    sel_label.fit()
    ngram.new_recording()
    for sc in training_syscalls:
        cnn.val_on(sc)
    cnn.fit()

    ngram.new_recording()
    # First 3 syscalls: ngram(4) not full yet -> None
    for i in range(3):
        result = cnn.get_result(training_syscalls[i])
        assert result is None, f"Expected None for syscall {i}, got {result}"

    # 4th syscall: ngram full -> score
    result = cnn.get_result(training_syscalls[3])
    assert result is not None


def test_cnn_select_callable_end():
    """Select with callable end should resolve after OHE.fit()."""
    ie = IntEmbedding()
    ohe = OneHotEncoding(ie)
    n = 3

    select = Select(ohe, start=0, end=lambda: ohe.get_embedding_size())

    # Before fit, OHE has no embeddings
    # After training and fit, the callable should resolve
    syscalls = [_sc(name, idx=i) for i, name in enumerate(['open', 'close', 'read'])]
    for sc in syscalls:
        ie.train_on(sc)
    ie.fit()
    for sc in syscalls:
        ohe.train_on(sc)
    ohe.fit()

    result = ohe.get_result(syscalls[0])
    assert result is not None
    selected = select.get_result(syscalls[0])
    assert selected is not None
    assert len(selected) == ohe.get_embedding_size()
