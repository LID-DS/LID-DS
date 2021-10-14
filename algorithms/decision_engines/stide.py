from base_decision_engine import BaseDecisionEngine
from collections import deque


class Stide(BaseDecisionEngine):

    def __init__(self, window_length):
        super().__init__()
        self._window_length = window_length
        self._normal_database = {}
        self._sliding_window = deque(maxlen=self._window_length)
        self._mismatch_count = 0


    def train_on(self, input_array):

        ngram = tuple(input_array)
        if not ngram in self._normal_database:
            self._normal_database[ngram] = 1

    def predict(self, input_array):

        ngram = tuple(input_array)
        if ngram in self._normal_database:
            mismatch = 0
        else:
            mismatch = 1

        self._mismatch_count -= self._sliding_window[0]
        if len(self._sliding_window) == self._window_length:
            self._mismatch_count += mismatch

        self._sliding_window.append(ngram)

        return self._mismatch_count/self._window_length




