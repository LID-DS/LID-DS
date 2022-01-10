from algorithms.building_block import BuildingBlock
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class StreamAverage(BuildingBlock):
    """
    gives the average value from a stream of system call features
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
        self._feature_id = self._sum.get_id()

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, features: dict):
        """
        returns the maximum value over feature in the window if the feature is in the current set of features
        """
        if self._feature_id in features:
            avg = features[self._feature_id] / self._window_length
            features[self.get_id()] = avg

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._sum.new_recording()
