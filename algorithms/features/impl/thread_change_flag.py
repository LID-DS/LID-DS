from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class ThreadChangeFlag(BuildingBlock):
    """
    if a ngram is full: check whether it has another thread id as the last seen ngram
    0 -> no change in thread id
    1 -> thread id changed or first thread id
    """

    def __init__(self, ngram: Ngram):
        super().__init__()
        self._last_thread_id = -1
        self._dependency_list = [ngram]
        self._ngram = ngram

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        value is 1 only for complete ngrams and a different tid as the last seen complete ngram
        """
        invalue = self._ngram.get_result(syscall)
        if invalue is not None:
            tcf = 0
            if syscall.thread_id() != self._last_thread_id:
                self._last_thread_id = syscall.thread_id()
                tcf = 1
            return tcf
        else:
            return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._last_thread_id = -1
