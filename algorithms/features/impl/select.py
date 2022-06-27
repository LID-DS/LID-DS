from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class Select(BuildingBlock):
    """
        Select range from start to end of BuildingBlock
    """

    def __init__(self,
                 input_vector: BuildingBlock,
                 start: int,
                 end: int,
                 step: int = 1):
        """
        """
        super().__init__()

        self._dependency_list = []
        self._dependency_list.append(input_vector)
        self._feature = input_vector
        self._start = start
        self._end = end
        self._step = step

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
            cut result of BuildingBlock to [start:end:step]

            Params:
                syscall(Syscall): syscall to extract result from
            Returns:

        """
        result = self._feature.get_result(syscall)
        if result is None:
            return None
        else:
            return result[self._start:self._end:self._step]
