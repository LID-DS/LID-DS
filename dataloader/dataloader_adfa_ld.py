import os
from enum import Enum

from base_data_loader import BaseDataLoader
from data_loader_2021 import RecordingType
from dataloader.recording_adfa_ld import RecordingADFALD

TRAINING = 'training'
VALIDATION = 'validation'
TEST = 'test'

class Attacks(Enum):
    Adduser = 1
    Hydra_FTP = 2
    Hydra_SSH = 3
    Java_Meterpreter = 4
    Meterpreter = 5
    Web_Shell = 6


class DataLoaderADFALD(BaseDataLoader):
    def __init__(self, path: str, attack: Attacks = None, validation_count: int = 200):
        super().__init__(scenario_path=path)
        self._normal_recordings = None
        self._exploit_recordings = None
        self._distinct_syscalls = None
        self._attack = attack
        self._validation_count = validation_count

    def training_data(self) -> list:
        recordings = self._extract_recordings(category=TRAINING)

        return recordings

    def validation_data(self) -> list:
        recordings = self._extract_recordings(category=VALIDATION)

        return recordings

    def test_data(self) -> list:
        recordings = self._extract_recordings(TEST)

        return recordings

    def _extract_recordings(self, category) -> list:
        train_dir = 'Training_Data_Master'
        val_dir = 'Validation_Data_Master'
        attack_dir = 'Attack_Data_Master'
        recordings = []

        if category == TRAINING:
            category_path = os.path.join(self.scenario_path, train_dir)
            recording_list = self._get_txt_files(category_path)

        elif category == VALIDATION:
            category_path = os.path.join(self.scenario_path, val_dir)
            recording_list = self._get_txt_files(category_path)
            recording_list.sort()
            recording_list = recording_list[:self._validation_count]

        elif category == TEST:
            attack_path = os.path.join(self.scenario_path, attack_dir)
            sub_dirs = os.listdir(attack_path)

            # filter attacks by dir name if specified
            if self._attack is not None:
                filtered_attack_dirs = []
                for dir_name in sub_dirs:
                    if dir_name.startswith(self._attack.name):
                        filtered_attack_dirs.append(dir_name)
                sub_dirs = filtered_attack_dirs

            attack_recordings = []
            for attack_sub_dir in sub_dirs:
                attack_recordings += self._get_txt_files(os.path.join(self.scenario_path, attack_dir, attack_sub_dir))

            val_path = os.path.join(self.scenario_path, val_dir)
            normal_test_recordings = self._get_txt_files(val_path)
            normal_test_recordings.sort()
            normal_test_recordings = normal_test_recordings[self._validation_count:]
            recording_list = normal_test_recordings + attack_recordings
        else:
            raise ValueError('unknown data category')

        for recording_path in recording_list:
            contains_attack = True if attack_dir in recording_path else False


            recordings.append(RecordingADFALD(recording_path, contains_attack))
        return recordings

    @staticmethod
    def _get_txt_files(path):
        file_list = []
        for file in os.listdir(path):
            if file.endswith('.txt'):
                file_list.append(os.path.join(path, file))
        return file_list


if __name__ == '__main__':
    dataloader = DataLoaderADFALD('/home/felix/datasets/ADFA-LD', attack=Attacks.Hydra_FTP)

    i = 1
    for recording in dataloader.test_data():
        for syscall in recording.syscalls():
            print(vars(syscall))
