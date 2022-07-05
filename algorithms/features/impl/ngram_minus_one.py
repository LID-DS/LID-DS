from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from dataloader.syscall import Syscall
from pprint import pprint

class NgramMinusOne(BuildingBlock):
    """

    calculate ngram form a stream of system call features
    remove last syscall feature in collect_features
    (Can be later used to fill in syscall int for prediction)

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
            k (int),v (list): key is ID of this class, ngram_value as tuple
        """
        ngram_value = self._ngram.get_result(syscall)
        #pprint(f"Current ngram: {ngram_value}")
        if ngram_value is not None:
                ngram_value = ngram_value[:-1]
                #pprint(f"Ngram minus one: {ngram_value}")
                return tuple(ngram_value)
        else:
            return None
