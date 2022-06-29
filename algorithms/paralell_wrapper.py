from dataloader.base_recording import BaseRecording
from dataloader.base_data_loader import BaseDataLoader

from algorithms.ids import IDS
from algorithms.performance_measurement import Performance

from tqdm.contrib.concurrent import process_map
from functools import reduce
from copy import deepcopy
from typing import Type


def _calculate(recording_ids_tuple: tuple) -> Performance:
    """
        create deepcopy of IDS and get performance object for recording of container

        Args:
        recroding_ids_tuple:
            ids: IDS with which perfomance is calculated
            recording: Recording on which performance is calculated
    """
    # Copy whole IDS with its BBs
    working_copy = deepcopy(recording_ids_tuple[0])
    # Calculate performance on current recording
    performance = working_copy.detect_on_single_recording(recording_ids_tuple[1])
    return performance


def parallel_detect(recordings: list, ids: IDS) -> Performance:
    """
        map reduce for every recording
        map:    first calculate performances with ids
        reduce: than sum up performances

        Args:
            recordings: list of recordings to analyze
            ids: IDS to analyze recordings with

        Returns:
            Performance: complete performance of all recordings

    """
    # creating list of Tuples with recordings and associated ids
    recording_ids_list = [(ids, recording) for recording in recordings]

    # parallel calculation for every recording
    performance_list = process_map(_calculate, recording_ids_list, chunksize = 2)

    # Sum up performances
    final_performance = reduce(Performance.add, performance_list)
    
    return final_performance
