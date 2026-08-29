"""
Building Block for frequency vector over a sliding window (Bag of System Calls).

Counts how often each distinct value appears in the current window
and returns the counts as a tuple. Compatible with Stide (exact lookup)
and vector-based decision engines (AE, SOM, MLP).
"""
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.int_embedding import IntEmbedding
from dataloader.syscall import Syscall


class FrequencyVector(BuildingBlock):
    """
    Sliding-window frequency counter.

    Wraps input in IntEmbedding if not already one, then maintains
    per-thread sliding windows and O(1) count updates.

    Output: tuple of ints (one count per vocab entry), length = vocab_size.
    """

    def __init__(self, feature: BuildingBlock, window_length: int,
                 thread_aware: bool = True):
        super().__init__()
        if isinstance(feature, IntEmbedding):
            self._int_emb = feature
        else:
            self._int_emb = IntEmbedding(feature)

        self._window_length = window_length
        self._thread_aware = thread_aware
        self._vocab_size = 0
        self._buffers = {}   # thread_id -> deque of ints
        self._counts = {}    # thread_id -> list[int]

        self._dependency_list = [self._int_emb]

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        idx = self._int_emb.get_result(syscall)
        if idx is not None and idx >= self._vocab_size:
            self._vocab_size = idx + 1

    def fit(self):
        print(f"freq_vector.vocab: {self._vocab_size}".rjust(27))

    def _calculate(self, syscall: Syscall):
        new_idx = self._int_emb.get_result(syscall)
        if new_idx is None:
            return None

        thread_id = syscall.thread_id() if self._thread_aware else 0
        buf = self._buffers.get(thread_id)
        if buf is None:
            buf = deque(maxlen=self._window_length)
            self._buffers[thread_id] = buf
            self._counts[thread_id] = [0] * self._vocab_size

        counts = self._counts[thread_id]

        # O(1) update: decrement dropout, increment new
        if len(buf) == self._window_length:
            old_idx = buf[0]
            counts[old_idx] -= 1

        buf.append(new_idx)
        if new_idx < self._vocab_size:
            counts[new_idx] += 1
        # else: unknown syscall (shouldn't happen — IntEmbedding maps unknowns to 0)

        if len(buf) < self._window_length:
            return None

        return tuple(counts)

    def new_recording(self):
        self._buffers = {}
        self._counts = {}
