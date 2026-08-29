import os
import glob
import json
import errno
import zipfile
import nest_asyncio
from tqdm import tqdm

from enum import Enum

from dataloader.direction import Direction
from dataloader.recording_2021 import Recording2021
from dataloader.base_data_loader import BaseDataLoader

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


class DataLoader2021(BaseDataLoader):
    """

        Recieves path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self, scenario_path, direction: Direction = Direction.BOTH,
                 cache_recordings: bool = False, max_cache_bytes: int = 8 * 1024**3,
                 permute_seed: int = None):
        super().__init__(scenario_path)
        self._permute_seed = permute_seed
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

        # Determine cache eligibility for train+val recordings
        # Estimate uncompressed .sc size: compressed_zip_size × 7.7 (ratio) × 0.89 (.sc share)
        self._cache_lines = False
        if cache_recordings:
            train_val_zips = (
                glob.glob(os.path.join(scenario_path, 'training', '*.zip')) +
                glob.glob(os.path.join(scenario_path, 'validation', '*.zip'))
            )
            compressed_bytes = sum(os.path.getsize(f) for f in train_val_zips if os.path.isfile(f))
            estimated_sc_bytes = int(compressed_bytes * 7.7 * 0.89)
            if estimated_sc_bytes <= max_cache_bytes:
                self._cache_lines = True
                print(f"  Line caching enabled (est. {estimated_sc_bytes / 1024**2:.0f} MB .sc <= {max_cache_bytes / 1024**3:.1f} GB limit)")
            else:
                print(f"  Line caching disabled (est. {estimated_sc_bytes / 1024**3:.1f} GB .sc > {max_cache_bytes / 1024**3:.1f} GB limit)")

        # Build and persist recordings once
        self._training_recordings = self._build_recordings(TRAINING)
        self._validation_recordings = self._build_recordings(VALIDATION)
        self._test_recordings = self._build_recordings(TEST, cache_lines=False)

        # patches missing nesting in asyncio needed for multiple consecutive pyshark extractions
        nest_asyncio.apply()

    def training_data(self, recording_type: RecordingType = None) -> list:
        if recording_type is None:
            return self._training_recordings
        return [r for r in self._training_recordings
                if self._metadata_list[TRAINING][r.name]['recording_type'] == recording_type]

    def validation_data(self, recording_type: RecordingType = None) -> list:
        if recording_type is None:
            return self._validation_recordings
        return [r for r in self._validation_recordings
                if self._metadata_list[VALIDATION][r.name]['recording_type'] == recording_type]

    def test_data(self, recording_type: RecordingType = None) -> list:
        if recording_type is None:
            return self._test_recordings
        return [r for r in self._test_recordings
                if self._metadata_list[TEST][r.name]['recording_type'] == recording_type]

    def _build_recordings(self, category: str, cache_lines: bool = None) -> list:
        if cache_lines is None:
            cache_lines = self._cache_lines
        recordings = []
        for file in sorted(self._metadata_list[category].keys()):
            recordings.append(Recording2021(
                name=file,
                path=self._metadata_list[category][file]['path'],
                direction=self._direction,
                cache_lines=cache_lines,
                permute_seed=self._permute_seed))
        return recordings

    def clear_cache(self):
        for recording in self._training_recordings + self._validation_recordings:
            recording.clear_cache()

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
        test_files = glob.glob(self.scenario_path + f'/{TEST}/*/*.zip')
        # create list of all files
        all_files = training_files + val_files + test_files
        for file in all_files:
            try:
                with zipfile.ZipFile(file, 'r') as zip_ref:
                    # remove zip extension and create json file name
                    json_file_name = get_file_name(file) + '.json'
                    with zip_ref.open(json_file_name) as unzipped:
                        unzipped_byte_json = unzipped.read()
                        unzipped_json = json.loads(unzipped_byte_json.decode('utf8'))
                        recording_type = get_type_of_recording(unzipped_json)
                        temp_dict = {
                            'recording_type': recording_type,
                            'path': file
                        }
                        if TRAINING in os.path.dirname(file):
                            metadata_dict[TRAINING][get_file_name(file)] = temp_dict
                        elif VALIDATION in os.path.dirname(file):
                            metadata_dict[VALIDATION][get_file_name(file)] = temp_dict
                        elif TEST in os.path.dirname(file):
                            metadata_dict[TEST][get_file_name(file)] = temp_dict
                        else:
                            raise TypeError()
            except zipfile.BadZipFile:
                name = file
                if not os.path.isfile('missing_files.txt'):
                    with open('missing_files.txt', 'w+') as file:
                        file.write(f'Bad zipfile in recording: {name}. \n')
                else:
                    with open('missing_files.txt', 'a') as file:
                        file.write(f'Bad zipfile in recording: {name}. \n')
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
    base_path = '../../Dataset/'
    scenario_names = os.listdir(base_path)
    for scenario in scenario_names:
        print(scenario)
        dataloader = DataLoader2021(base_path + scenario)
        function_list = [dataloader.training_data,
                         dataloader.validation_data,
                         dataloader.test_data]
        for f in function_list:
            data = f()
            for recording in tqdm(data):
                pass
