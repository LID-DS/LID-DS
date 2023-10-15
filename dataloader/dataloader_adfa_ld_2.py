import os
from enum import Enum

from dataloader.base_data_loader import BaseDataLoader
from dataloader.recording_adfa_ld_2 import RecordingADFALDFixed

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


class DataLoaderFixedADFALD(BaseDataLoader):
    def __init__(self,
                 path: str,
                 attack: Attacks = None,
                 val_count: int = 200,
                 val_train_add: int = 500,
                 test_normal_count: int = 400):
        """
            Dataloader for the ADFA-LD dataset
            Handles Training, Validation and Test Data
            Attacks can be filtered

            @param path: ADFA-LD Base Path
            @param attack: ADFA-LD attack recording that will be loaded
            @param val_count: number of validation data files
            @param val_train_add: number of recordings from validation directory that will be added to training data
        """
        super().__init__(scenario_path=path)
        self._normal_recordings = None
        self._exploit_recordings = None
        self._distinct_syscalls = None
        self._attack = attack
        self._validation_count = val_count
        self._val_train_add = val_train_add
        self._test_normal_count = test_normal_count

    def training_data(self) -> list:
        """
        creates list of recordings containing training data
        @return: list of training data recordings
        """
        recordings = self._extract_recordings(category=TRAINING)

        return recordings

    def validation_data(self) -> list:
        """
        creates list of recordings containing validation data
        @return: list of validation data recordings
        """
        recordings = self._extract_recordings(category=VALIDATION)

        return recordings

    def test_data(self) -> list:
        """
        creates list of recordings containing test data (benign + attack data)
        @return: list of test data recordings
        """
        recordings = self._extract_recordings(TEST)

        return recordings

    def _extract_recordings(self, category: str) -> list:
        """
        extracts different recordings by data category
        handles the attack filter
        @param category: one of the data categories (Training, Validation, Test)
        @return: list of Recording objects
        """
        train_dir = 'Training_Data_Master'
        val_dir = 'Validation_Data_Master'
        attack_dir = 'Attack_Data_Master'
        recordings = []

        # distinguishing categories
        if category == TRAINING:
            train_path = os.path.join(self.scenario_path, train_dir)
            training_list = self._get_txt_files(train_path)
            val_path = os.path.join(self.scenario_path, val_dir)
            normal_train_recordings = self._get_txt_files(val_path)
            normal_train_recordings.sort()
            normal_train_recordings = normal_train_recordings[:self._val_train_add]
            recording_list = training_list + normal_train_recordings

        elif category == VALIDATION:
            category_path = os.path.join(self.scenario_path, val_dir)
            recording_list = self._get_txt_files(category_path)
            recording_list.sort()
            recording_list = recording_list[self._val_train_add:self._val_train_add + self._validation_count]

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

            # attack files are located in another subdirectory
            attack_recordings = []
            for attack_sub_dir in sub_dirs:
                attack_recordings += [os.path.join(self.scenario_path, attack_dir, attack_sub_dir)]

            val_path = os.path.join(self.scenario_path, val_dir)
            normal_test_recordings = self._get_txt_files(val_path)
            normal_test_recordings.sort()
            normal_test_recordings = normal_test_recordings[self._validation_count + self._val_train_add:
                                                            self._validation_count + self._val_train_add + self._test_normal_count]
            recording_list = normal_test_recordings + attack_recordings
        else:
            raise ValueError('unknown data category')

        for recording_path in recording_list:
            # check for attack files
            contains_attack = True if attack_dir in recording_path else False
            recordings.append(RecordingADFALDFixed(recording_path, contains_attack))
        return recordings

    @staticmethod
    def _get_txt_files(path):
        """
        ectracts all .txt file from a directory
        @param path: directory path
        @return: list of text files
        """
        file_list = []
        for file in os.listdir(path):
            if file.endswith('.txt'):
                file_list.append(os.path.join(path, file))
        return file_list


if __name__ == '__main__':
    dataloader = DataLoaderFixedADFALD('/home/tini/informatik/ma/Datasets/ADFA/ADFA-LD')

    collected_syscalls = {}
    for recording in dataloader.test_data():
        collected_syscalls[recording.path] = []
        for syscall in recording.syscalls():
            collected_syscalls[recording.path].append(syscall)
