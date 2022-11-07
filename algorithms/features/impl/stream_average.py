from algorithms.features.impl.stream_sum import StreamSum
from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class StreamAverage(BuildingBlock):
    """
    gives the average value from a stream of bbs
    """

    def __init__(self, feature: BuildingBlock, thread_aware: bool, window_length: int):
        """
        feature: the average should be calculated on feature
        thread_aware: True or False
        window_length: length of the window considered
        """
        super().__init__()
        self._feature = feature
        self._window_length = window_length

        self._dependency_list = []
        self._sum = StreamSum(feature, thread_aware, window_length)
        self._dependency_list.append(self._sum)

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        returns the average value over the bb in the window or None if the feature is None
        """
        input = self._sum.get_result(syscall)
        if input is not None:        
            return input / self._window_length            
        else:
            return None
