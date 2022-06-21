from collections import deque
from pprint import pprint

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall

class Stide(BuildingBlock):

    def __init__(self, input: BuildingBlock, window_length=100):
        super().__init__()
        # parameter
        self._window_length = window_length
        self._input = input

        # internal data
        self._normal_database = set()
        self._sliding_window = deque(maxlen=self._window_length)
        self._mismatch_count = 0

        # dependency list
        self._dependency_list = []
        self._dependency_list.append(self._input)

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
        creates a set for distinct ngrams from training data
        """
        ngram = self._input.get_result(syscall)
        if ngram != None:            
            if ngram not in self._normal_database:
                self._normal_database.add(ngram)
                #pprint(f"Added N-Gram: {ngram}")
    def fit(self):
        print(f"stide.train_set: {len(self._normal_database)}".rjust(27))

    def _calculate(self, syscall: Syscall):
        """
        calculates ratio of unknown ngrams in sliding window of current recording
        """
        ngram = self._input.get_result(syscall)
        if ngram is not None:
            if ngram in self._normal_database:
                mismatch = 0
            else:
                mismatch = 1
                #pprint(f"Stide: N-Gram not in database: {ngram}, name: {syscall.name()}, thread-id: {syscall.thread_id()}")
            if len(self._sliding_window) == self._window_length:
                self._mismatch_count -= self._sliding_window[0]
            self._mismatch_count += mismatch
            self._sliding_window.append(mismatch)
            return self._mismatch_count / self._window_length
        else:
            return None

    def new_recording(self):
        self._sliding_window.clear()
        self._mismatch_count = 0
