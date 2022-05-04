
import numpy as np

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from dataloader.syscall import Syscall


class StreamVariance(BuildingBlock):
    """
    calculate the variance within the given ngram        
    """

    def __init__(self, ngram: Ngram):
        super().__init__()
        self._dependency_list = []
        self._dependency_list.append(ngram)
        self._ngram = ngram        

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        Returns:
            nothing if no ngram exists
            variance of the elements in the ngram otherwise
        """
        ngram_value = self._ngram.get_result(syscall)
        if ngram_value is not None:
                return np.var(ngram_value)
        else:
            return None
