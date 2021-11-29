from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ProcessID(BaseFeature, metaclass=Singleton):

    def __init__(self):
        super().__init__()

    def extract(self, syscall: Syscall, features: dict):
        """
        extract process ID of syscall
        """
        features[self.get_id()] = syscall.process_id()

    def depends_on(self):
        return []
