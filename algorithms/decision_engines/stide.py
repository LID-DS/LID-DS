from collections import deque

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine


class Stide(BaseDecisionEngine):

    def __init__(self, window_length):
        super().__init__()
        self._window_length = window_length
        self._normal_database = {}
        self._sliding_window = deque(maxlen=self._window_length)
        self._mismatch_count = 0

    def train_on(self, input_array):

        """
        creates dict for distinct ngrams from training data
            key: ngram
            value: 1

        """

        ngram = tuple(input_array)
        if not ngram in self._normal_database:
            self._normal_database[ngram] = 1

    def predict(self, input_array):

        """
        calculates ratio of unknown ngrams in sliding window of current recording

        """
        ngram = tuple(input_array)
        if ngram in self._normal_database:
            mismatch = 0
        else:
            mismatch = 1

        if len(self._sliding_window) == self._window_length:
            self._mismatch_count -= self._sliding_window[0]

        self._mismatch_count += mismatch
        self._sliding_window.append(mismatch)

        return self._mismatch_count / self._window_length

    def new_recording(self):

        self._sliding_window.clear()
        self._mismatch_count = 0
