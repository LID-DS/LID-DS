import errno
import glob
import json
import os
import zipfile
from enum import Enum

import nest_asyncio
from tqdm import tqdm

from dataloader.base_data_loader import BaseDataLoader
from dataloader.direction import Direction
from dataloader.recording_ctf import RecordingCTF

TRAINING = 'training'
VALIDATION = 'validation'
TEST = 'test'


class RecordingType(Enum):
    NORMAL = 1
    NORMAL_AND_ATTACK = 2
    ATTACK = 3
    IDLE = 4


def get_file_name(path: str) -> str:
    """
        Return file name without path and extension

        Parameter:
        path (str): path of file

        Returns:
        str: file name

    """
    return os.path.splitext(os.path.basename(path))[0]


def get_type_of_recording(json_dict: dict) -> RecordingType:
    """

        Receives json dict and determines the recording type.

        Parameter:
        json_dict (dict): json including metadata

        Returns:
        RecordingType: Enumeration describing type

    """
    data = json_dict

    normal_behavior = False
    exploit = False

    # check for normal behaviour:
    for container in data["container"]:
        if container["role"] == "normal":
            normal_behavior = True
            break
    # check for exploit
    if data["exploit"]:
        exploit = True

    if normal_behavior is False and exploit is False:
        return RecordingType.IDLE
    if normal_behavior is False and exploit is True:
        return RecordingType.ATTACK
    if normal_behavior is True and exploit is False:
        return RecordingType.NORMAL
    if normal_behavior is True and exploit is True:
        return RecordingType.NORMAL_AND_ATTACK


class DataLoaderCTF(BaseDataLoader):
    """

        Recieves path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self, scenario_path, direction: Direction = Direction.BOTH):
        """

            Save path of scenario and create metadata_list.

            Parameter:
            scenario_path (str): path of assosiated folder

        """
        super().__init__(scenario_path)
        if os.path.isdir(scenario_path):
            self.scenario_path = scenario_path
            self._direction = direction
            self._metadata_list = self.collect_metadata()
            self._distinct_syscalls = None
        else:
            print(f'Could not find {scenario_path}!!!!')
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENONET),
                scenario_path
            )

        # patches missing nesting in asyncio needed for multiple consecutive pyshark extractions
        nest_asyncio.apply()

    def training_data(self, recording_type: RecordingType = None) -> list:
        """

            Create list of recordings contained in training data.
            Specify recordings with recording_type.

            Parameter:
            recording_type (RecordingType): only include recordings of recording_type
                :default: all included

            Returns:
            list: list of training data recordings

        """
        recordings = self.extract_recordings(category=TRAINING,
                                             recording_type=recording_type)
        return recordings

    def validation_data(self, recording_type: RecordingType = None) -> list:
        """

            Create list of recordings contained in validation data.
            Specify recordings with recording_type.

            Parameter:
            recording_type (RecordingType): only include recordings of recording_type
                :default: all included

            Returns:
            list: list of validation data recordings

        """
        recordings = self.extract_recordings(category=VALIDATION,
                                             recording_type=recording_type)
        return recordings

    def test_data(self, recording_type: RecordingType = None) -> list:
        """

            Create list of recordings contained in test data.
            Specify recordings with recording_type.

            Parameter:
            recording_type (RecordingType): only include recordings of recording_type
                :default: all included

            Returns:
            list: list of test data recordings

        """
        recordings = self.extract_recordings(category=TEST,
                                             recording_type=recording_type)
        return recordings

    def extract_recordings(self,
                           category: str,
                           recording_type: RecordingType = None) -> list:
        """

            Go through list of all files in specified category.
            Instanciate new Recording object and append to recordings list.
            If all files have been seen return list of Recordings.

            Parameter:
            category (str): filter for category (training, validation, test)
            recording_type (RecordingType): only include recordings of recording_type
                :default: all included

            Returns:
            list: list of data recordings for specified category


        """
        recordings = []
        file_list = sorted(self._metadata_list[category].keys())
        for file in file_list:
            # check filter
            if recording_type:
                if self._metadata_list[category][file]['recording_type'] == recording_type:
                    recordings.append(RecordingCTF(name=file,
                                                   path=self._metadata_list[category][file]['path'],
                                                   direction=self._direction))
            else:
                recordings.append(RecordingCTF(name=file,
                                               path=self._metadata_list[category][file]['path'],
                                               direction=self._direction))
        return recordings

    def collect_metadata(self) -> dict:
        """

            Create dictionary which contains following information about recording:
                first key: Category of recording : training, validataion, test
                second key: Name of recording
                value : {recording type: str, path: str}

            Returns:
            dict: metadata_dict containing type of recording for every recorded file

        """
        metadata_dict = {
            'training': {},
            'validation': {},
            'test': {}
        }
        training_files = glob.glob(self.scenario_path + f'/{TRAINING}/*.json')
        val_files = glob.glob(self.scenario_path + f'/{VALIDATION}/*.json')
        test_files = glob.glob(self.scenario_path + f'/{TEST}/*/*.json')
        # create list of all files
        all_files = training_files + val_files + test_files

        for file in all_files:
            if file.endswith('.json'):
                with open(file) as json_file:
                    json_read_data = json.load(json_file)
                    recording_type = get_type_of_recording(json_read_data)
                    temp_dict = {
                        'recording_type': recording_type,
                        'path': os.path.splitext(file)[0]
                    }

                    if TRAINING in os.path.dirname(file):
                        metadata_dict[TRAINING][get_file_name(file)] = temp_dict
                    elif VALIDATION in os.path.dirname(file):
                        metadata_dict[VALIDATION][get_file_name(file)] = temp_dict
                    elif TEST in os.path.dirname(file):
                        metadata_dict[TEST][get_file_name(file)] = temp_dict
                    else:
                        raise TypeError()

        return metadata_dict

    def distinct_syscalls_training_data(self) -> int:
        """

        calculate distinct syscall names in training data
        try to load from file json file in training folder

        Returns:
        int: distinct syscalls in training data

        """
        json_path = '/training/distinct_syscalls.json'
        try:
            with open(self.scenario_path + json_path, 'r') as distinct_syscalls:
                distinct_json = json.load(distinct_syscalls)
                self._distinct_syscalls = distinct_json['distinct_syscalls']
        except Exception:
            print('Could not load distinct syscalls. Calculating now...')

        if self._distinct_syscalls is not None:
            return self._distinct_syscalls
        else:
            syscall_dict = {}
            description = 'Calculating distinct syscalls'.rjust(25)
            for recording in tqdm(self.training_data(), description, unit=' recording'):
                for syscall in recording.syscalls():
                    if syscall.name() in syscall_dict:
                        continue
                    else:
                        syscall_dict[syscall.name()] = True
            self._distinct_syscalls = len(syscall_dict)
            with open(self.scenario_path + json_path, 'w') as distinct_syscalls:
                json.dump({'distinct_syscalls': self._distinct_syscalls}, distinct_syscalls)
            return self._distinct_syscalls


if __name__ == "__main__":
    path = '/home/felix/datasets/CVE-2017-7529_LTTng_CTF_sample'
    dataloader = DataLoaderCTF(path)
    function_list = [dataloader.training_data,
                     dataloader.validation_data,
                     dataloader.test_data]
    for f in function_list:
        data = f()
        for recording in data:
            for syscall in recording.syscalls():
                print(syscall.name())
