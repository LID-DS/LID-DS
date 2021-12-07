import os
from dataloader.syscall import Syscall


class Alarm:
    def __init__(self, syscall: Syscall, correct: bool):
        self.current_line_id = syscall.line_id
        self.current_timestamp = syscall.timestamp_datetime()
        self.scenario = None
        self.dataset = None
        self.correct = correct
        self.filepath = syscall.recording_path
        self._determine_dataset(syscall.recording_path)
        self._determine_scenario(syscall.recording_path)

    def _determine_dataset(self, path):
        if '.zip' in path:
            self.dataset = 'LID-DS-2021'
        else:
            self.dataset = 'LID-DS-2019'

    def _determine_scenario(self, path):
        if self.dataset == 'LID-DS-2019':
            self.scenario = os.path.basename(self.filepath)
        else:
            basename = os.path.basename(self.filepath)
            if basename == 'training' or basename == 'validation':
                self.scenario = os.path.split(self.filepath)[-3]
            elif basename == 'normal' or basename == 'normal_and_attack':
                self.scenario = os.path.split(self.filepath)[-4]


