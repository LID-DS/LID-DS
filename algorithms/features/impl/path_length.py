import math
import typing

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class PathLength(BuildingBlock):
    def __init__(self):
        """
        """
        super().__init__()
        self._min = math.inf
        self._max = -math.inf

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        return []

    def _get_valid_fd_or_none(self, params) -> typing.Union[str, None]:
        """
        checks syscall params for file descriptor tags and calculates its value if present, if not it returns None
        Returns:
            value of file descriptor param or None
        """
        param_names = ['fd', 'in_fd', 'out_fd']  # params to investigate
        for param in param_names:
            if param in params:
                fd = params[param]
                if '<f>' in fd:
                    return fd
        return None

    def train_on(self, syscall: Syscall, features: dict):
        fd = self._get_valid_fd_or_none(syscall.params())
        if fd is not None:
            current_len = len(fd)
            if current_len < self._min:
                self._min = current_len
            if current_len > self._max:
                self._max = current_len

    def calculate(self, syscall: Syscall, features: dict):
        """
        """
        fd = self._get_valid_fd_or_none(syscall.params())
        if fd is not None:
            features[self.get_id()] = (len(fd) - self._min) / (self._max - self._min)
