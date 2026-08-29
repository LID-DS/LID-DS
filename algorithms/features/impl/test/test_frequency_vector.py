import pytest

from algorithms.features.impl.frequency_vector import FrequencyVector
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall_2021 import Syscall2021


def _sc(name, tid=1, idx=0):
    return Syscall2021('test/rec.zip',
                       f"100000000{idx} 0 {tid} proc 1 {name} < res=0")


def test_frequency_vector_counts_and_vocab():
    """The frequency vector counts each vocabulary entry within the window."""
    ie = IntEmbedding()
    fv = FrequencyVector(ie, window_length=3, thread_aware=False)

    names = ['open', 'read', 'write', 'open', 'open']
    syscalls = [_sc(name, idx=i) for i, name in enumerate(names)]

    # Training phase: build the vocabulary (ints start at 1, 0 = unknown)
    for sc in syscalls:
        ie.train_on(sc)
    ie.fit()
    fv.fit()

    vocab_size = len(ie._syscall_dict) + 1
    assert vocab_size == 4

    # Detection: window fills up after 3 syscalls
    results = [fv.get_result(sc) for sc in syscalls]
    assert results[0] is None
    assert results[1] is None

    # After 3 syscalls (open, read, write): one count per entry
    assert results[2] == (0, 1, 1, 1)

    # After 5 syscalls (open, read, write, open, open):
    # window holds last 3 = (write, open, open) -> open=2, write=1, read=0
    assert results[4] == (0, 2, 0, 1)
    assert len(results[4]) == vocab_size


def test_frequency_vector_thread_aware_buffers():
    """Thread-aware mode maintains separate windows per thread."""
    ie = IntEmbedding()
    fv = FrequencyVector(ie, window_length=2, thread_aware=True)

    names = ['open', 'read', 'write', 'open']
    tids = [1, 2, 1, 2]
    syscalls = [_sc(name, tid=tid, idx=i) for i, (name, tid) in enumerate(zip(names, tids))]

    for sc in syscalls:
        ie.train_on(sc)
    ie.fit()
    fv.fit()

    results = [fv.get_result(sc) for sc in syscalls]

    # Thread 1 has seen (open, write) after syscall 3 -> window full
    assert results[0] is None
    assert results[1] is None
    assert results[2] is not None
    assert results[3] is not None

    # The two threads have independent windows: their vectors differ
    assert results[2] != results[3]

    # Thread 1's vector counts only thread 1 syscalls (open and write)
    assert sum(results[2]) == 2


def test_frequency_vector_wraps_non_int_embedding_features():
    """A feature that is not an IntEmbedding is wrapped automatically."""
    sn = SyscallName()
    fv = FrequencyVector(sn, window_length=2)
    assert isinstance(fv.depends_on()[0], IntEmbedding)
    assert fv.depends_on()[0] is not sn
