import typing
from collections import deque
from collections.abc import Iterable

from algorithms.building_block import BuildingBlock
from algorithms.features.impl import threadID
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class Dgram(BuildingBlock):
    """
    calculate dgram form a stream of system call features
    """

    def __init__(self, feature_list: list, thread_aware: bool, min_length=2):
        """
        feature_list: list of features the dgram should use
        thread_aware: True or False
        """
        super().__init__()
        self._dgram_buffer = {}
        self._dgram_value_set = {}
        self._list_of_feature_ids = []
        for feature in feature_list:
            self._list_of_feature_ids.append(feature.get_id())
        self._thread_aware = thread_aware        
        self._min_length = min_length
        self._dependency_list = []
        self._dependency_list.extend(feature_list)

    def depends_on(self):
        return self._dependency_list

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        writes the dgram into dependencies if its complete
        otherwise does not write into dependencies
        """
        check = all(i in dependencies for i in self._list_of_feature_ids)
        if check is True:
            thread_id = 0
            if self._thread_aware:
                thread_id = syscall.thread_id()
            if thread_id not in self._dgram_buffer:
                self._dgram_buffer[thread_id] = deque()
                self._dgram_value_set[thread_id] = set()
            self._dgram_buffer[thread_id].append(dependencies)
            
            # check whether the current value already is in the current dgram
            current_value = ""
            for id in self._list_of_feature_ids:
                current_value += str(dependencies[id]) + "-"
            #print(f"current: {current_value}")
            #print(f"    set: {self._dgram_value_set[thread_id]}")
            
            if current_value in self._dgram_value_set[thread_id] and len(self._dgram_buffer[thread_id]) >= self._min_length:
                dgram_value = self._collect_features(self._dgram_buffer[thread_id])
                dependencies[self.get_id()] = tuple(dgram_value)
                #print(f"result: {dgram_value}")
                self._dgram_value_set[thread_id] = set()
                self._dgram_buffer[thread_id] = deque()
            else:
                self._dgram_value_set[thread_id].add(current_value)
        

    def _collect_features(self, deque_of_dicts: deque) -> list:
        """
        in:  a deque of dictionaries like {feature_id_1: value_1, feature_id_2: value_2}
        out: the dgram consisting of the selected features
        """
        array = []
        for feature_dict in deque_of_dicts:
            for feature_id in self._list_of_feature_ids:
                if feature_id in feature_dict:
                    if isinstance(feature_dict[feature_id], Iterable):
                        if isinstance(feature_dict[feature_id], str):
                            array.append(feature_dict[feature_id])
                        else:
                            array.extend(feature_dict[feature_id])
                    else:
                        array.append(feature_dict[feature_id])
        return array

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._dgram_buffer = {}
        self._dgram_value_set = {}
