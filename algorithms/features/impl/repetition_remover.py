import typing
from collections import deque
from collections.abc import Iterable

from algorithms.building_block import BuildingBlock
from algorithms.features.impl import threadID
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall import Syscall


class RepetitionRemover(BuildingBlock):
    """
    this bb removes consecutive repetitions of the same input from the stream
    example:
    input:  1 2 2 3 1 2 3 3 3 1
    output: 1 2   3 1 2 3     1
    """

    def __init__(self, input: BuildingBlock, thread_aware: bool):
        """
        input: feature to filter
        thread_aware: True or False
        """
        super().__init__()
        self._last_inputs = {}        
        self._feature_id = input.get_id()
        self._feature = input
        self._thread_aware = thread_aware        
        self._dependency_list = [input]

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, syscall: Syscall):
        """
        checks whehter the input differs from the last seen input
        yes: writes input to output
        no: writes None to output
        """
        # get input
        input = self._feature.get_result(syscall)
        if input is not None:
            # get tid
            tid = 0
            if self._thread_aware:
                tid = syscall.thread_id()
 
            # check if we already saw tid
            if tid not in self._last_inputs:
                # no so write to output
                self._last_inputs[tid] = input
                return input
            else:
                # yes we already saw tid
                # check if input differs from last_input                
                if input != self._last_inputs[tid]:
                    # yes it differs, write to output
                    self._last_inputs[tid] = input
                    return input
                else:
                    # otherwise its the same... write None
                    return None
        else:
            return None
                
    def new_recording(self):
        """
        emptys buffers
        """
        self._last_inputs = {}        
