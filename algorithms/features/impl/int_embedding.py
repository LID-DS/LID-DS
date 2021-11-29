import typing

from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class IntEmbedding(BaseFeature, metaclass=Singleton):
    """
        convert system call name to unique integer
    """

    def __init__(self):
        super().__init__()
        self._syscall_dict = {}

    def depends_on(self):
        return []

    def train_on(self, syscall: Syscall, features: dict):
        """
            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls
        """
        if syscall.name() not in self._syscall_dict:
            self._syscall_dict[syscall.name()] = len(self._syscall_dict) + 1

    def extract(self, syscall: Syscall, features: dict):
        """
            transforms given syscall name to integer
        """
        try:
            sys_to_int = self._syscall_dict[syscall.name()]
        except KeyError:
            sys_to_int = 0
        features[self.get_id()] = sys_to_int
