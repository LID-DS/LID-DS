import os
import glob
import json
import errno
from enum import Enum
from tqdm import tqdm
from zipfile import ZipFile, ZIP_DEFLATED


from dataloader.direction import Direction
from dataloader.base_data_loader import BaseDataLoader
from dataloader.recording_real_world import RecordingRealWorld


TRAINING = 'training'
VALIDATION = 'validation'
TEST = 'test'


class RecordingType(Enum):
    NORMAL = 1
    NORMAL_AND_ATTACK = 2


def get_type_of_recording(path: str) -> RecordingType:
    """
        Receives file path and determines the recording type.
        -> Check if malicious is included in file name 
        Parameter:
        path (str): path of zip file
        Returns:
        RecordingType: Enumeration describing type
    """
    if 'malicious' in path:
        return RecordingType.NORMAL_AND_ATTACK
    else:
        return RecordingType.NORMAL


def get_file_name(path: str) -> str:
    """
        Return file name without path and extension
        Parameter:
        path (str): path of file
        Returns:
        str: file name
    """
    return os.path.splitext(os.path.basename(path))[0]


def convert_all_scap(path: str) -> bool:
    """
        Convert all (train, val, test) scap filesto compressed .sc files
        Remove .scap and .sc files

        Parameter:
        path (str): path to scenario
        Returns:
        bool: False if Exception was thrown
    """
    try:
        training_files = glob.glob(path + f'/{TRAINING}/*.scap')
        val_files = glob.glob(path + f'/{VALIDATION}/*.scap')
        test_files = glob.glob(path + f'/{TEST}/*.scap')
        scap_files = training_files + val_files + test_files
        for file in scap_files:
            # file[:-2] cuts .scap ending to .sc
            sc_file = file[:-2]
            os.system(f'sysdig -v -b -p "%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %syscall.type %evt.dir %evt.args" -r {file} "proc.pid != -1" > {sc_file}')
            ZipFile(f'{file[:-4]}zip',
                    mode='w',
                    compresslevel=8,
                    compression=ZIP_DEFLATED).write(
                        filename=f'{file[:-2]}',
                        arcname=os.path.split(sc_file)[1])
            # remove scap file
            os.remove(file)
            # remove sc file
            os.remove(sc_file)
        return True
    except Exception:
        return False


class DataLoaderRealWorld(BaseDataLoader):
    """

        Recieves path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self,
                 scenario_path: str,
                 direction: Direction = Direction.BOTH):
        """

            Save path of scenario and create metadata_list.

            Parameter:
            scenario_path (str): path of assosiated folder

        """
        super().__init__(scenario_path)
        convert_all_scap(scenario_path)
        if os.path.isdir(scenario_path):
            self.scenario_path = scenario_path
            self._direction = direction
            self._metadata_dict = self.collect_metadata()
            self._distinct_syscalls = None
        else:
            print(f'Could not find {scenario_path}!!!!')
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENONET),
                scenario_path
            )

        self.scenario_path = scenario_path
        print(f"loading {scenario_path}")

    def training_data(self) -> list:
        """

            Create list of recordings contained in training data.
            Specify recordings with recording_type.

            Returns:
            list: list of training data recordings

        """
        recordings = self.extract_recordings(category=TRAINING)
        return recordings

    def validation_data(self) -> list:
        """

            Create list of recordings contained in validation data.
            Specify recordings with recording_type.

            Returns:
            list: list of validation data recordings

        """
        recordings = self.extract_recordings(category=VALIDATION)
        return recordings

    def test_data(self) -> list:
        """

            Create list of recordings contained in test data.
            Specify recordings with recording_type.

            Returns:
            list: list of test data recordings

        """
        recordings = self.extract_recordings(category=TEST)
        return recordings

    def extract_recordings(self, 
                           category: str,
                           recording_type: RecordingType=None) -> list:
        """

            Go through list of all files in specified category.
            Instanciate new Recording object and append to recordings list.
            If all files have been seen return list of Recordings.

            Parameter:
            category (str): filter for category (training, validation, test)
            recording_type (RecordingType): filter for REcording direction

            Returns:
            list: list of data recordings for specified category


        """
        recordings = []
        file_list = sorted(self._metadata_dict[category].keys())
        for file in file_list:
            # check filter
            recordings.append(RecordingRealWorld(name=file,
                                                 path=self._metadata_dict[category][file]['sc_path'],
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
        training_files = glob.glob(self.scenario_path + f'/{TRAINING}/*.zip')
        val_files = glob.glob(self.scenario_path + f'/{VALIDATION}/*.zip')
        test_files = glob.glob(self.scenario_path + f'/{TEST}/*.zip')
        all_files = training_files + val_files + test_files
        for file in all_files:
            file_name = os.path.dirname(file)
            recording_type = get_type_of_recording(file)
            temp_dict = {
                'recording_type': recording_type,
                'sc_path': file,
            }
            if TRAINING in file_name:
                metadata_dict[TRAINING][get_file_name(file)] = temp_dict
            elif VALIDATION in file_name:
                metadata_dict[VALIDATION][get_file_name(file)] = temp_dict
            elif TEST in file_name:
                metadata_dict[TEST][get_file_name(file)] = temp_dict
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
