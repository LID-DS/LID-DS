from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from dataloader.syscall import Syscall


class NgramMinusOne(BuildingBlock):
    """

    calculate ngram form a stream of system call features
    remove last syscall feature in collect_features
    (Can be later used to fill in syscall int for prediction)

    """

    def __init__(self, ngram: Ngram, element_size: int = None):
        super().__init__()
        self._dependency_list = []
        self._dependency_list.append(ngram)
        self._ngram = ngram
        self._element_size = element_size

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        Returns:
            nothing if no ngram exists
            k (int),v (list): key is ID of this class, ngram_value as tuple
        """
        ngram_value = self._ngram.get_result(syscall)
        if ngram_value is not None:
            if self._element_size is None:
                self._element_size = len(ngram_value) // self._ngram._ngram_length - 1
            return ngram_value[:-self._element_size]
        else:
            return None
