import typing

from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ThreadID(BaseFeature, metaclass=Singleton):

    def __init__(self):
        pass

    def extract(self, syscall: Syscall, features: dict) -> typing.Tuple[int, int]:
        """

        extract thread ID of syscall

        """
        return ThreadID.get_id(), syscall.thread_id()

    def depends_on(self):
        return []

    def new_recording(self):
        pass
