import typing

from dataloader.syscall import Syscall
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class ReturnValue(BaseSyscallFeatureExtractor):

    def __init__(self):
        super().__init__()
        self._max_time_delta = 0
        self._last_time = {}
        self.type_dict = {}

    def train_on(self, syscall: Syscall):
        """

        calc max time delta

        """
        param = syscall.param('res')
        print(param)
        if param:
            self.type_dict[type(param)] = 1
        # delta = self._calc_delta(current_time, syscall)
        # if delta > self._max_time_delta:
        # self._max_time_delta = delta

    def fit(self):
        print(self.type_dict)

    def extract(self, syscall: Syscall) -> typing.Tuple[int, float]:
        """

        extract thread ID of syscall

        """
        current_time = syscall.timestamp_datetime()
        delta = self._calc_delta(current_time, syscall)
        normalized_delta = delta / self._max_time_delta
        return ReturnValue.get_id(), normalized_delta
