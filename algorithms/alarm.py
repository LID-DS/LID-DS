import os
from dataloader.syscall import Syscall


class Alarm:
    def __init__(self, syscall: Syscall, correct: bool):
        """
            represents one alarm as object
            differentiates between LID-DS-2019 and LID-DS-2021

            args:
            syscall: Syscall Object
            correct: flag if the current alarm is correct detected
        """
        self.first_line_id = syscall.line_id
        self.first_timestamp = syscall.timestamp_unix_in_ns()
        self.correct = correct

        self.last_line_id = None
        self.last_timestamp = None
        self.scenario = None
        self.dataset = None
        self.filepath = None

        self._determine_dataset(syscall.recording_path)
        self._determine_scenario(syscall.recording_path)
        self._determine_filepath(syscall.recording_path)

    def _determine_dataset(self, path):
        """
            determines the current syscall's dataset

            args:
                path: path of recording
        """
        if '.zip' in path:
            self.dataset = 'LID-DS-2021'
        else:
            self.dataset = 'LID-DS-2019'

    def _determine_scenario(self, path):
        """
            determines the current scenario based on syscall

            args:
                path: path of recording
        """
        if self.dataset == 'LID-DS-2019':
            self.scenario = os.path.basename(os.path.dirname(path))
        else:
            dirname = os.path.basename(os.path.dirname(path))
            if dirname == 'training' or dirname == 'validation':
                self.scenario = path.split('/')[-3]
            elif dirname == 'normal' or dirname == 'normal_and_attack':
                self.scenario = path.split('/')[-4]

    def _determine_filepath(self, path):
        """
            cuts the filepath based on scenario

            args:
             path: path of recording
        """
        index = path.find(self.scenario)
        self.filepath = path[index:]


