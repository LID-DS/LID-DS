import math

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class NgramEntropy(BuildingBlock):
    """
        Given an ngram (s_1, ... s_n)
        calculates the conditional entropy for the probability of s_n given (s_1,...s_n-1)
        based on paper: DOI: 10.1109/DISCEX.2001.932213
            - used to determine an optimal ngram length: lowest entropy

        Note: This is not a proper BuildingBlock and cannot be used as an intermediary step
    """

    def __init__(self, input_vector: BuildingBlock):
        super().__init__()
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self.training_set = []
        self.validation_set = []
        self.entropy_train_val = None
        self.entropy_val_train = None

    def train_on(self, syscall):
        input_array: tuple = self._input_vector.get_result(syscall)
        if input_array is not None:
            self.training_set.append(input_array)

    def val_on(self, syscall):
        input_array: tuple = self._input_vector.get_result(syscall)
        if input_array is not None:
            self.validation_set.append(input_array)

    def fit(self):
        self.entropy_train_val = self._calculate_entropy(self.training_set, self.validation_set)
        self.entropy_val_train = self._calculate_entropy(self.validation_set, self.training_set)

    @staticmethod
    def _calculate_entropy(ngrams_train, ngrams_val):
        co_occurrences_count = {}
        for ngram in ngrams_train:
            ngram_minus_1 = ngram[:-1]
            last_ngram = ngram[-1]
            if ngram_minus_1 not in co_occurrences_count:
                co_occurrences_count[ngram_minus_1] = {}
            if last_ngram not in co_occurrences_count[ngram_minus_1]:
                co_occurrences_count[ngram_minus_1][last_ngram] = 0
            co_occurrences_count[ngram_minus_1][last_ngram] += 1

        probabilities = {}
        for ngram_minus_1, n_dict in co_occurrences_count.items():
            total = sum(n_dict.values())
            for last_ngram, count in n_dict.items():
                probabilities[ngram_minus_1 + (last_ngram,)] = count / total

        conditional_entropy = 0
        for ngram in ngrams_val:
            conditional_entropy -= 1 / len(ngrams_val) * math.log(probabilities.get(ngram, 0.0000001), 2)

        return conditional_entropy

    def get_result(self) -> dict:
        return {
            'entropy_train_val': self.entropy_train_val,
            'entropy_val_train': self.entropy_val_train
        }

    def _calculate(self, syscall: Syscall):
        pass

    def depends_on(self) -> list:
        """

        returns list of features this decision engine depends on

        """
        return self._dependency_list
