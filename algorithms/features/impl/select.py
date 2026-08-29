from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Select(BuildingBlock):
    """
        Select range or single element from BuildingBlock result.
        Use index for scalar extraction, start/end for slicing.

        start/end/index may be int or callable (resolved on first _calculate).
        This allows deferred sizing, e.g. when OHE embedding size is unknown
        at construction time:
            Select(ngram, start=0, end=lambda: n * ohe.get_embedding_size())
    """

    def __init__(self,
                 input_vector: BuildingBlock,
                 start=None,
                 end=None,
                 step: int = 1,
                 index=None):
        super().__init__()
        if index is not None and (start is not None or end is not None):
            raise ValueError("Use either 'index' or 'start/end', not both")
        if index is None and start is None and end is None:
            raise ValueError("Must provide either 'index' or 'start/end'")

        self._dependency_list = []
        self._dependency_list.append(input_vector)
        self._feature = input_vector
        self._start = start
        self._end = end
        self._step = step
        self._index = index
        self._resolved = False

    def _resolve_callables(self):
        if self._resolved:
            return
        if callable(self._start):
            self._start = self._start()
        if callable(self._end):
            self._end = self._end()
        if callable(self._index):
            self._index = self._index()
        self._resolved = True

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        result = self._feature.get_result(syscall)
        if result is None:
            return None
        if not self._resolved:
            self._resolve_callables()
        if self._index is not None:
            return result[self._index]
        return result[self._start:self._end:self._step]
