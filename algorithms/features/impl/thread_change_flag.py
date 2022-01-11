from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ThreadChangeFlag(BuildingBlock, metaclass=Singleton):
    """
    if a ngram is full: check whether it has another thread id as the last seen ngram
    0 -> no change in thread id
    1 -> thread id changed or first thread id
    """

    def __init__(self, ngram: Ngram):
        super().__init__()
        self._last_thread_id = 0
        self._dependency_list = [ThreadID(), ngram]
        self._ngram = ngram

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, features: dict):
        """
        value is 1 only for complete ngrams and a different tid as the last seen complete ngram
        """
        tcf = 0
        if self._ngram.get_id() in features:        
            if syscall.thread_id() != self._last_thread_id:
                self._last_thread_id = syscall.thread_id()
                tcf = 1
        features[self.get_id()] = tcf

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._last_thread_id = 0
