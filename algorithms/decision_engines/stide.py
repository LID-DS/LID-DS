"""
Building Block implementing the STIDE algorithm
"""
from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock


class Stide(BuildingBlock):
    """
    Training: save seen Building Blocks into normal "database"
    Inference: check if current input is in normalbase return 0 if that is the case
    """
    def __init__(self, input: BuildingBlock):
        super().__init__()
        # parameter
        self._input = input

        # internal data
        self._normal_database = set()

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
        if ngram is not None:
            if ngram not in self._normal_database:
                self._normal_database.add(ngram)

    def fit(self):
        print(f"stide.train_set: {len(self._normal_database)}".rjust(27))

    def _calculate(self, syscall: Syscall):
        """
        calculates ratio of unknown ngrams in sliding window of current recording
        """
        ngram = self._input.get_result(syscall)
        if ngram is not None:
            if ngram in self._normal_database:
                return 0
            return 1
        return None
