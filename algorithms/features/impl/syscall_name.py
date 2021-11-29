import typing

from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class SyscallName(BaseFeature, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def extract(self, syscall: Syscall, features: dict):
        """
        extract name of syscall
        """
        features[self.get_id()] = syscall.name()

    def depends_on(self):
        return []
