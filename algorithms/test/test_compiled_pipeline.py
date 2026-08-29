"""
Differential tests for compiled pipeline vs original get_result().

Runs both paths on the same syscall sequences and asserts identical results.
"""
import pytest
from collections import deque

from algorithms.compiled_pipeline import compile_pipeline, _topo_sort
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.and_decider import AndDecider
from algorithms.features.impl.or_decider import OrDecider
from algorithms.decision_engines.stide import Stide

from dataloader.syscall_2021 import Syscall2021


# ── Helpers ───────────────────────────────────────────────────────────

# Syscall2021 format: "timestamp uid pid pname tid syscall_name direction params..."
def _sc(tid, name, res=0):
    return f'1631264236000000000 0 100 proc {tid} {name} < res={res}'

TRAIN_LINES = [
    _sc(1, 'read', 5),
    _sc(1, 'write', 10),
    _sc(1, 'close', 0),
    _sc(1, 'open', 3),
    _sc(1, 'stat', 0),
    _sc(1, 'read', 5),
    _sc(1, 'write', 10),
    _sc(1, 'read', 5),
    _sc(2, 'read', 5),
    _sc(2, 'write', 10),
    _sc(2, 'open', 3),
    _sc(2, 'close', 0),
    _sc(2, 'read', 5),
    _sc(2, 'stat', 0),
    _sc(2, 'write', 10),
    _sc(2, 'read', 5),
]

TEST_LINES = [
    _sc(1, 'read', 5),
    _sc(1, 'write', 10),
    _sc(1, 'close', 0),
    _sc(1, 'open', 3),
    _sc(1, 'mmap', 0),    # unknown syscall
    _sc(1, 'read', 5),
    _sc(1, 'write', 10),
    _sc(1, 'stat', 0),
    _sc(2, 'read', 5),
    _sc(2, 'brk', 0),     # unknown syscall
    _sc(2, 'write', 10),
    _sc(2, 'open', 3),
    _sc(2, 'close', 0),
    _sc(2, 'read', 5),
    _sc(2, 'stat', 0),
    _sc(2, 'write', 10),
]


def _make_syscalls(lines):
    return [Syscall2021('', line) for line in lines]


def _build_stide_pipeline(ngram_length=5, thread_aware=True, window_length=50):
    """Build a standard STIDE pipeline: IE -> Ngram -> Stide -> StreamSum -> MST."""
    ie = IntEmbedding()
    ngram = Ngram([ie], thread_aware, ngram_length)
    stide = Stide(ngram)
    ss = StreamSum(stide, False, window_length, False)
    mst = MaxScoreThreshold(ss)
    return mst


def _build_and_pipeline():
    """Build an AND-ensemble pipeline (two STIDE branches)."""
    ie1 = IntEmbedding()
    ngram1 = Ngram([ie1], True, 3)
    stide1 = Stide(ngram1)
    ss1 = StreamSum(stide1, False, 10, False)
    mst1 = MaxScoreThreshold(ss1)

    ie2 = IntEmbedding()
    ngram2 = Ngram([ie2], True, 5)
    stide2 = Stide(ngram2)
    ss2 = StreamSum(stide2, False, 10, False)
    mst2 = MaxScoreThreshold(ss2)

    return AndDecider([mst1, mst2])


def _build_stream_avg_pipeline():
    """Build pipeline with StreamAverage instead of StreamSum."""
    ie = IntEmbedding()
    ngram = Ngram([ie], True, 3)
    stide = Stide(ngram)
    sa = StreamAverage(stide, False, 10)
    mst = MaxScoreThreshold(sa)
    return mst


def _train_pipeline(final_bb, syscalls):
    """Train all BBs in topological order."""
    nodes = _topo_sort(final_bb)
    for syscall in syscalls:
        for node in nodes:
            node.train_on(syscall)
    for node in nodes:
        node.fit()


def _val_pipeline(final_bb, syscalls):
    """Run validation on all BBs."""
    nodes = _topo_sort(final_bb)
    for syscall in syscalls:
        for node in nodes:
            node.val_on(syscall)
    # Reset after val
    for node in nodes:
        node.new_recording()


def _run_both(final_bb, test_syscalls):
    """Run both compiled and original on same syscalls, return paired results."""
    compiled_fn = compile_pipeline(final_bb)
    original_results = []
    compiled_results = []

    for syscall in test_syscalls:
        orig = final_bb.get_result(syscall)
        original_results.append(orig)

    # Reset state for compiled run
    nodes = _topo_sort(final_bb)
    for node in nodes:
        node.new_recording()

    for syscall in test_syscalls:
        comp = compiled_fn(syscall)
        compiled_results.append(comp)

    return original_results, compiled_results


# ── Tests ─────────────────────────────────────────────────────────────

def test_topo_sort_basic():
    """Topo sort produces leaves-first order."""
    mst = _build_stide_pipeline(ngram_length=3)
    nodes = _topo_sort(mst)
    assert isinstance(nodes[0], SyscallName)
    assert isinstance(nodes[-1], MaxScoreThreshold)


def test_topo_sort_shared_nodes():
    """Shared nodes are only included once."""
    ie = IntEmbedding()
    ngram1 = Ngram([ie], True, 3)
    ngram2 = Ngram([ie], True, 5)
    stide1 = Stide(ngram1)
    stide2 = Stide(ngram2)
    ss1 = StreamSum(stide1, False, 10, False)
    ss2 = StreamSum(stide2, False, 10, False)
    mst1 = MaxScoreThreshold(ss1)
    mst2 = MaxScoreThreshold(ss2)
    final = AndDecider([mst1, mst2])

    nodes = _topo_sort(final)
    node_ids = [id(n) for n in nodes]
    assert len(node_ids) == len(set(node_ids)), "Duplicate nodes in topo sort"


def test_stide_pipeline_differential():
    """Compiled STIDE pipeline produces identical results to original."""
    train_sc = _make_syscalls(TRAIN_LINES)
    test_sc = _make_syscalls(TEST_LINES)

    final_bb = _build_stide_pipeline(ngram_length=3, window_length=10)
    _train_pipeline(final_bb, train_sc)
    _val_pipeline(final_bb, train_sc)

    orig, comp = _run_both(final_bb, test_sc)
    assert orig == comp, f"Mismatch:\norig={orig}\ncomp={comp}"


def test_and_decider_differential():
    """Compiled AND-ensemble produces identical results to original."""
    train_sc = _make_syscalls(TRAIN_LINES)
    test_sc = _make_syscalls(TEST_LINES)

    final_bb = _build_and_pipeline()
    _train_pipeline(final_bb, train_sc)
    _val_pipeline(final_bb, train_sc)

    orig, comp = _run_both(final_bb, test_sc)
    assert orig == comp, f"Mismatch:\norig={orig}\ncomp={comp}"


def test_stream_average_differential():
    """Compiled StreamAverage pipeline produces identical results."""
    train_sc = _make_syscalls(TRAIN_LINES)
    test_sc = _make_syscalls(TEST_LINES)

    final_bb = _build_stream_avg_pipeline()
    _train_pipeline(final_bb, train_sc)
    _val_pipeline(final_bb, train_sc)

    orig, comp = _run_both(final_bb, test_sc)
    assert orig == comp, f"Mismatch:\norig={orig}\ncomp={comp}"


def test_compiled_source_available():
    """Compiled function has _source attribute for debugging."""
    final_bb = _build_stide_pipeline(ngram_length=3)
    _train_pipeline(final_bb, _make_syscalls(TRAIN_LINES))

    fn = compile_pipeline(final_bb)
    assert hasattr(fn, '_source')
    assert 'def _pipeline(syscall):' in fn._source


def test_debug_output(capsys):
    """Debug mode prints source code."""
    final_bb = _build_stide_pipeline(ngram_length=3)
    _train_pipeline(final_bb, _make_syscalls(TRAIN_LINES))

    fn = compile_pipeline(final_bb, debug=True)
    captured = capsys.readouterr()
    assert 'Compiled Pipeline Source' in captured.out


def test_multi_recording_reset():
    """State resets correctly between recordings via new_recording()."""
    train_sc = _make_syscalls(TRAIN_LINES)
    test_sc = _make_syscalls(TEST_LINES)

    final_bb = _build_stide_pipeline(ngram_length=3, window_length=5)
    _train_pipeline(final_bb, train_sc)
    _val_pipeline(final_bb, train_sc)

    compiled_fn = compile_pipeline(final_bb)
    nodes = _topo_sort(final_bb)

    # Run recording 1
    results_r1 = []
    for syscall in test_sc:
        results_r1.append(compiled_fn(syscall))

    # Reset
    for node in nodes:
        node.new_recording()

    # Run recording 2 (same data)
    results_r2 = []
    for syscall in test_sc:
        results_r2.append(compiled_fn(syscall))

    assert results_r1 == results_r2, "State reset failed between recordings"


def test_wait_until_full_true():
    """StreamSum with wait_until_full=True returns None until window is full."""
    ie = IntEmbedding()
    ngram = Ngram([ie], True, 3)
    stide = Stide(ngram)
    ss = StreamSum(stide, False, 5, True)  # wait_until_full=True
    mst = MaxScoreThreshold(ss)

    train_sc = _make_syscalls(TRAIN_LINES)
    _train_pipeline(mst, train_sc)
    _val_pipeline(mst, train_sc)

    orig, comp = _run_both(mst, _make_syscalls(TEST_LINES))
    assert orig == comp


def test_or_decider():
    """Compiled OR-decider produces identical results."""
    ie1 = IntEmbedding()
    ngram1 = Ngram([ie1], True, 3)
    stide1 = Stide(ngram1)
    ss1 = StreamSum(stide1, False, 5, False)
    mst1 = MaxScoreThreshold(ss1)

    ie2 = IntEmbedding()
    ngram2 = Ngram([ie2], True, 5)
    stide2 = Stide(ngram2)
    ss2 = StreamSum(stide2, False, 5, False)
    mst2 = MaxScoreThreshold(ss2)

    final_bb = OrDecider([mst1, mst2])

    train_sc = _make_syscalls(TRAIN_LINES)
    _train_pipeline(final_bb, train_sc)
    _val_pipeline(final_bb, train_sc)

    orig, comp = _run_both(final_bb, _make_syscalls(TEST_LINES))
    assert orig == comp
