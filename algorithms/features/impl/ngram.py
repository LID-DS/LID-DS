import typing
from collections import deque
from collections.abc import Iterable
from algorithms import features

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class Ngram(BuildingBlock):
    """
    calculate ngram form a stream of system call features
    """

    def __init__(self, feature_list: list, thread_aware: bool, ngram_length: int):
        """
        feature_list: list of features the ngram should use
        thread_aware: True or False
        ngram_length: length of the ngram
        """
        super().__init__()
        self._ngram_buffer = {}
        self._thread_aware = thread_aware
        self._ngram_length = ngram_length
        # calculate this value later
        self._deque_length = None
        self._dependency_list = []
        self._dependency_list.extend(feature_list)

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        writes the ngram into dependencies if its complete
        otherwise does not write into dependencies
        """
        dependencies = []
        all_dependencies_are_not_none = True
        # call get_result on each dependency
        # build the ngram if all dependencies are not None
        for feature in self._dependency_list:
            result = feature.get_result(syscall)
            if result is None:
                all_dependencies_are_not_none = False
            else:
                Ngram._concat(result, dependencies)

        # if all dependencies are not none: build the ngram 
        if all_dependencies_are_not_none:

            # get the length of one ngram element
            # example: a 3-gram can consist of
            # 3 strings
            # 3 2-element arrays
            # and so on

            if self._deque_length is None:
                self._deque_length = self._ngram_length * len(dependencies)
            
            # group by thread id            
            thread_id = syscall.thread_id() if self._thread_aware else 0
            if thread_id not in self._ngram_buffer:                
                self._ngram_buffer[thread_id] = deque(maxlen=self._deque_length)

            # append the current dependencies to the ngram
            self._ngram_buffer[thread_id].extend(dependencies)
            # return the ngram if its complete
            if len(self._ngram_buffer[thread_id]) == self._deque_length:                
                return tuple(self._ngram_buffer[thread_id])
        return None

    def _concat(source_value, target_vector):
        """
        the source_value (could be a Iterable, str or other) is concated to target_vector (array)
        """        
        if isinstance(source_value, Iterable):
            if isinstance(source_value, str):
                # source is iterable, but its a string -> call append
                target_vector.append(source_value)
            else:
                # source is iterable and no string -> call extend
                target_vector.extend(source_value)
        else:
            # source is not iterable: just call append
            target_vector.append(source_value)


    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._ngram_buffer = {}
