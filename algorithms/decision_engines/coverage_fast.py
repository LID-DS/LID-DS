"""
Building Block implementing the Coverage algorithm
"""
import numpy as np
import ahocorasick
import matplotlib.pyplot as plt

from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock


class CoverageFast(BuildingBlock):
    """
    Training: save seen Building Blocks into normal "database"
    Inference: calculate how many bbs from training are in the current sequence 
    """
    def __init__(self, short_sequence: BuildingBlock, long_sequence: BuildingBlock):
        super().__init__()
        # for histogram
        self._num_bins = 100
        self._bins = np.zeros(self._num_bins+1)
        
        # parameter
        self._short_sequence = short_sequence
        self._long_sequence = long_sequence

        # internal data
        self._normal_database = set()
        self._automaton = ahocorasick.Automaton(ahocorasick.STORE_INTS)        
        # self._automaton = ahocorasick.Automaton()
        self._automaton_build = False
        self._val_max_seen_coverage = 0
        self._val_min_seen_coverage = 9999999

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
            self._normal_database.add(ngram_str)            

    def val_on(self, syscall: Syscall):
        """
        
        """
        if self._automaton_build is False:
            self._automaton_build = True
            self._build_automaton()

        long_sequence = self._long_sequence.get_result(syscall)
        if long_sequence is not None:
            current_coverage = self._count_occurrences(long_sequence)
            
            if current_coverage > self._val_max_seen_coverage:
                self._val_max_seen_coverage = current_coverage
                # print(f"max_cov_val = {current_coverage}")
            
            if current_coverage < self._val_min_seen_coverage:
                self._val_min_seen_coverage = current_coverage
                # print(f"min_cov_val = {current_coverage}")

    def _build_automaton(self):
        # create aho-corasick-automaton with patterns        
        for pattern in self._normal_database:
            # print(pattern)
            self._automaton.add_word(pattern)            
        self._automaton.make_automaton()

    def fit(self):
        #print(self._normal_database)
        print(f"coverage.train_set: {len(self._normal_database)}".rjust(27))
        print(f"min/max = [{self._val_min_seen_coverage},{self._val_max_seen_coverage}]")
        print(f"val coverage.max: {1.0 - self._val_min_seen_coverage / (1+self._val_max_seen_coverage):.3f}".rjust(27))
        print(f"val coverage.min: {1.0 - self._val_max_seen_coverage / (1+self._val_max_seen_coverage):.3f}".rjust(27))

    def _calculate(self, syscall: Syscall):
        """
        calculates number of seen short sequences from training in the current long sequence
        """
        long_sequence = self._long_sequence.get_result(syscall)
        if long_sequence is not None:
            current_coverage = 1.0 - self._count_occurrences(long_sequence) / (1+self._val_max_seen_coverage)
            
            # for histogram
            index = max(0,int(current_coverage * self._num_bins))
            self._bins[index] += 1

            # return result
            return current_coverage
        return None

    def _count_occurrences(self, long_sequence):
        long_sequence_str = ''.join(str(x) + " " for x in long_sequence)
        count = 0
        for _, __ in self._automaton.iter(long_sequence_str):
            count += 1        
        return count

    def draw_histogram(self, threshold):
        self._bins /= self._bins.sum()
        plt.bar(np.linspace(0, 1, self._num_bins+1), self._bins, width=1.0/self._num_bins)
        plt.xlabel('Value')
        plt.ylabel('Frequency')
        plt.title('Histogram')
        plt.yscale('log')
        plt.axvline(threshold, color='r', linestyle='--')
        plt.savefig('histogram.png', dpi=300, bbox_inches='tight')
        plt.close()