"""
Building Block implementing the Coverage algorithm
"""
from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock


class Coverage(BuildingBlock):
    """
    Training: save seen Building Blocks into normal "database"
    Inference: calculate how many bbs from training are in the current sequence 
    """
    def __init__(self, short_sequence: BuildingBlock, long_sequence: BuildingBlock):
        super().__init__()
        # parameter
        self._short_sequence = short_sequence
        self._long_sequence = long_sequence

        # internal data
        self._normal_database = set()        
        self._val_max_seen_coverage = 0
        self._val_min_seen_coverage = 9999999

        self._test_max_seen_coverage = 0
        self._test_min_seen_coverage = 9999999

        # dependency list
        self._dependency_list = [self._short_sequence, self._long_sequence]        

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
        creates a set for distinct ngrams from training data
        """
        ngram = self._short_sequence.get_result(syscall)
        if ngram is not None:
            ngram_str = ''.join(str(x) + " " for x in ngram)
            if ngram_str not in self._normal_database:
                self._normal_database.add(ngram_str)

    def val_on(self, syscall: Syscall):
        """
        
        """        
        long_sequence = self._long_sequence.get_result(syscall)
        if long_sequence is not None:
            current_coverage = self._count_occurrences(long_sequence)
            if current_coverage > self._val_max_seen_coverage:
                self._val_max_seen_coverage = current_coverage
            if current_coverage < self._val_min_seen_coverage:
                self._val_min_seen_coverage = current_coverage

    def fit(self):
        print(f"coverage.train_set: {len(self._normal_database)}".rjust(27))
        print(f"val coverage.worst: {1.0 - self._val_min_seen_coverage / (1+self._val_max_seen_coverage):.3f}".rjust(27))
        print(f"val coverage.best: {1.0 - self._val_max_seen_coverage / (1+self._val_max_seen_coverage):.3f}".rjust(27))

    def stats(self):
        print(f"test coverage.worst: {self._test_max_seen_coverage:.3f}".rjust(27))
        print(f"test coverage.best: {self._test_min_seen_coverage:.3f}".rjust(27))

    def _calculate(self, syscall: Syscall):
        """
        calculates number of seen short sequences from training in the current long sequence
        """
        long_sequence = self._long_sequence.get_result(syscall)
        if long_sequence is not None:
            current_coverage = 1.0 - (self._count_occurrences(long_sequence) / (1+self._val_max_seen_coverage))
            if current_coverage > self._test_max_seen_coverage:
                self._test_max_seen_coverage = current_coverage
            if current_coverage < self._test_min_seen_coverage:
                self._test_min_seen_coverage = current_coverage
            return current_coverage
        return None

    def _count_occurrences(self, long_sequence):
        count = 0
        long_sequence_str = ''.join(str(x) + " " for x in long_sequence)
        for short_sequence_str in self._normal_database:     
            count += long_sequence_str.count(short_sequence_str)
        return count
