import typing

from algorithms.features.base_feature import BaseFeature
from algorithms.features.ngram import Ngram
from algorithms.features.threadID import ThreadID
from dataloader.syscall import Syscall


class ThreadChangeFlag(BaseFeature):
    """
    if a ngram is full: check whether it has another thread id as the last seen ngram
    0 -> no change in thread id
    1 -> thread id changed
    """

    def __init__(self):
        """
        """
        self._last_thread_id = 0

        self._dependency_list = []
        self._dependency_list.append(ThreadID())

    def depends_on(self):
        return self._dependency_list

    def extract(self, syscall: Syscall, features: dict) -> typing.Tuple[str, list]:
        """
        only returns not None if ngram exists
        """
        tcf = 0
        if Ngram.get_id() in features:
            if syscall.thread_id() != self._last_thread_id:
                self._last_thread_id = syscall.thread_id()
                tcf = 1
        return ThreadChangeFlag.get_id(), tcf

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._last_thread_id = 0
