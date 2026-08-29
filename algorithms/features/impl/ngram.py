import typing
from collections import deque
from collections.abc import Iterable
from algorithms import features

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class Ngram(BuildingBlock):
    """
    calculate ngram form a stream of system call features
    """

    def __init__(self, feature_list: list, thread_aware: bool, ngram_length: int):
        """
        feature_list: list of features the ngram should use
        thread_aware: True or False
        ngram_length: length of the ngram
        """
        super().__init__()
        self._ngram_buffer = {}
        self._thread_aware = thread_aware
        self._ngram_length = ngram_length
        self._deque_length = None
        self._dependency_list = []
        self._dependency_list.extend(feature_list)
        # Pre-bind get_result methods to avoid repeated attribute lookup
        self._dep_getters = [f.get_result for f in feature_list]
        # Concat strategy (compiled on first valid call)
        self._concat_mask = None

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        writes the ngram into dependencies if its complete
        otherwise does not write into dependencies
        """
        results = []
        for getter in self._dep_getters:
            result = getter(syscall)
            if result is None:
                return None
            results.append(result)

        # Compile concat mask on first successful call
        if self._concat_mask is None:
            self._concat_mask = tuple(
                type(v) is not str and hasattr(v, '__iter__') for v in results
            )
            flat_len = sum(len(v) if m else 1 for m, v in zip(self._concat_mask, results))
            self._deque_length = self._ngram_length * flat_len

        # Build flat dependencies using pre-compiled mask
        if not any(self._concat_mask):
            deps = results
        else:
            deps = []
            for is_iter, v in zip(self._concat_mask, results):
                if is_iter:
                    deps.extend(v)
                else:
                    deps.append(v)

        thread_id = syscall.thread_id() if self._thread_aware else 0
        buf = self._ngram_buffer.get(thread_id)
        if buf is None:
            buf = deque(maxlen=self._deque_length)
            self._ngram_buffer[thread_id] = buf

        buf.extend(deps)
        if len(buf) == self._deque_length:
            return tuple(buf)
        return None


    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._ngram_buffer = {}
