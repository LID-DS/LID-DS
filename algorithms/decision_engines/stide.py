from collections import deque

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall
from algorithms.features.impl.ngram import Ngram

class Stide(BuildingBlock):

    def __init__(self, ngram: Ngram, window_length=100):
        super().__init__()
        # parameter
        self._window_length = window_length
        self._ngram = ngram

        # internal data
        self._normal_database = set()
        self._sliding_window = deque(maxlen=self._window_length)
        self._mismatch_count = 0

        # dependency list
        self._dependency_list = []
        self._dependency_list.append(self._ngram)

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall, dependencies: dict):
        """
        creates a set for distinct ngrams from training data
        """
        if self._ngram.get_id() in dependencies:
            ngram = dependencies[self._ngram.get_id()]
            if ngram not in self._normal_database:
                self._normal_database.add(ngram)
            
    def fit(self):
        # print(self._normal_database)
        # print(f"STIDE normal db: {len(self._normal_database)}")
        pass

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        calculates ratio of unknown ngrams in sliding window of current recording
        """
        if self._ngram.get_id() in dependencies:
            ngram = dependencies[self._ngram.get_id()]   
            if ngram in self._normal_database:
                mismatch = 0
            else:
                mismatch = 1
            if len(self._sliding_window) == self._window_length:
                self._mismatch_count -= self._sliding_window[0]
            self._mismatch_count += mismatch
            self._sliding_window.append(mismatch)
            dependencies[self.get_id()] = self._mismatch_count / self._window_length

    def new_recording(self):
        self._sliding_window.clear()
        self._mismatch_count = 0
