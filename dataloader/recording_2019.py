import os
from syscall_2019 import Syscall
from distutils.util import strtobool

from enum import IntEnum


class RecordingDataParts(IntEnum):
    IMAGE_NAME = 0
    RECORDING_NAME = 1
    IS_EXECUTING_EXPLOIT = 2
    WARMUP_TIME = 3
    RECORDING_TIME = 4
    EXPLOIT_START_TIME = 5


class Recording:
    """

    Single Recording built out of one line from runs.csv of LID-DS 2019

    Args:
        recording_data_list (list): runs.csv line as list
        base_path (str): the base path of the LID-DS 2019 scenario

    """
    def __init__(self, recording_data_list: list, base_path: str):
        self.recording_data_list = recording_data_list
        self._metadata = self._collect_metadata()
        self.name = self._metadata['name']
        self.path = os.path.join(base_path, f'{self.name}.txt')

    def syscalls(self) -> Syscall:
        with open(self.path, 'r') as recording_file:
            for syscall in recording_file:
                yield Syscall(syscall)

    def _collect_metadata(self):
        return {
            'image': self.recording_data_list[RecordingDataParts.IMAGE_NAME],
            'name': self.recording_data_list[RecordingDataParts.RECORDING_NAME],
            'exploit': strtobool(self.recording_data_list[RecordingDataParts.IS_EXECUTING_EXPLOIT].lower()),
            'recording_time': int(self.recording_data_list[RecordingDataParts.RECORDING_TIME]),
            'time': {
                'exploit': {
                    'relative': int(self.recording_data_list[RecordingDataParts.EXPLOIT_START_TIME])
                },
                'warmup_end': {
                    'relative': {
                        'relative': int(self.recording_data_list[RecordingDataParts.WARMUP_TIME])
                    }
                }
            }
        }

    def metadata(self) -> dict:
        return self._metadata
