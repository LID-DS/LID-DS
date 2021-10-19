import os
import csv
import random
from dataloader.recording_2019 import Recording

TRAINING_SIZE = 200
VALIDATION_SIZE = 50


class DataLoader:
    """

    Loads data for LID-DS 2019 dataset

    Args:
          scenario_path (str): path to LID-DS 2019 scenario

    """
    def __init__(self, scenario_path: str):
        self._scenario_path = scenario_path
        self._runs_path = os.path.join(scenario_path, 'runs.csv')
        self._normal_recordings = None
        self._exploit_recordings = None
        self._distinct_syscalls = None

        self.extract_recordings()

    def training_data(self) -> list:
        """

        Returns:
            list of training data

        """
        return self._normal_recordings[:TRAINING_SIZE]

    def validation_data(self) -> list:
        """

                Returns:
                    list of validation data

                """
        return self._normal_recordings[TRAINING_SIZE:TRAINING_SIZE + VALIDATION_SIZE]

    def test_data(self) -> list:
        """

                Returns:
                    list of test data

                """
        recordings = self._normal_recordings[TRAINING_SIZE + VALIDATION_SIZE:] + self._exploit_recordings
        random.shuffle(recordings)

        return recordings

    def extract_recordings(self):
        """

        extracts and sorts normal and exploited recordings apart


        """
        with open(self._runs_path, 'r') as runs_csv:
            recording_reader = csv.reader(runs_csv, skipinitialspace=True)
            next(recording_reader)

            normal_recordings = []
            exploit_recordings = []

            for recording_line in recording_reader:
                recording = Recording(recording_line, self._scenario_path)
                if not recording.metadata()['exploit']:
                    normal_recordings.append(recording)
                else:
                    exploit_recordings.append(recording)

        self._normal_recordings = normal_recordings
        self._exploit_recordings = exploit_recordings

    def distinct_syscalls_training_data(self):
        """

        calculate distinct syscall names in training data

        Returns:
        int: distinct syscalls in training data

        """
        if self._distinct_syscalls is not None:
            return self._distinct_syscalls
        else:
            syscall_dict = {}
            for recording in self.training_data():
                for syscall in recording.syscalls():
                    if syscall.name() in syscall_dict:
                        continue
                    else:
                        syscall_dict[syscall.name()] = True
            self._distinct_syscalls = len(syscall_dict)
            print(self._distinct_syscalls)
            return self._distinct_syscalls
