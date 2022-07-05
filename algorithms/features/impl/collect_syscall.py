from dataloader.syscall import Syscall
from dataloader.direction import Direction

from algorithms.building_block import BuildingBlock


class CollectSyscall(BuildingBlock):
    """
        Summarize information of opening and closing step of syscall.
        Only works if both directions of syscalls are being used in dataloader.

        Feature: Return syscall only if closing part of syscall is completed.
                 Result of given BBs in input_list for every syscalls are returned.
    """

    def __init__(self, feature_list: list):
        """
        """
        super().__init__()
        self._buffer = {}
        self._feature_result_dict = {}

        self._dependency_list = []
        self._dependency_list.extend(feature_list)

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall) -> tuple:
        """
            Keep buffer for every thread.
            If second syscall with same name in same thread appears it must be closing one.
            Evaluate all results of features.

            Params:
                syscall: Syscall
            Returns:
                tuple() 
        """
        thread_id = syscall.thread_id()
        syscall_name = syscall.name()
        # create new buffer for given thread_id
        if thread_id not in self._buffer:
            self._buffer[thread_id] = {}
        # if syscall not in thread buffer
        # create new syscall_name buffer
        if syscall_name not in self._buffer[thread_id]:
            # if first syscall is closing one, discard it
            if syscall.direction() == Direction.CLOSE:
                return None
            self._buffer[thread_id][syscall_name] = {}
            closing_syscall = False
        else:
            closing_syscall = True
        # save features in dict for syscall
        for feature in self._dependency_list:
            feature_name = type(feature).__name__
            feature_result = feature.get_result(syscall)
            self._buffer[thread_id][syscall_name][feature_name] = feature_result
        if closing_syscall:
            result_list = []
            for feature in self._dependency_list:
                result_list.append(self._buffer[thread_id][syscall_name][type(feature).__name__])
            self._buffer[thread_id][syscall_name] = {}
            return tuple(result_list)
        else:
            return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._buffer = {}
