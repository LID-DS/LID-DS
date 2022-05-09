import os
import glob
import errno
import nest_asyncio

from enum import Enum

from dataloader.direction import Direction
from dataloader.base_data_loader import BaseDataLoader


TRAINING = 'training'
VALIDATION = 'validation'
TEST = 'test'


class RecordingType(Enum):
    NORMAL = 1
    NORMAL_AND_ATTACK = 2


def get_type_of_recording(path: str) -> RecordingType:
    """
        Receives file path and determines the recording type.
        -> Check if json with attack start time for file exists.
        Parameter:
        path (str): path of scap file
        Returns:
        RecordingType: Enumeration describing type
    """
    # splitext: ../../file.txt -> ("../../file", ".txt")
    file_without_extension = os.path.splitext(path)[0]
    if os.path.exists(file_without_extension + '.json'):
        return RecordingType.ATTACK
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



class RealWorldDataLoader(BaseDataLoader):
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
        super().__init__(scenario_path, direction)
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
        self.scenario_path = scenario_path
        print(f"loading {scenario_path}")

    def training_data(self) -> list:
        """

            Create list of recordings contained in training data.
            Specify recordings with recording_type.

            Returns:
            list: list of training data recordings

        """11
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

    def extract_recordings(self, category: str) -> list:
        """

            Go through list of all files in specified category.
            Instanciate new Recording object and append to recordings list.
            If all files have been seen return list of Recordings.

            Parameter:
            category (str): filter for category (training, validation, test)

            Returns:
            list: list of data recordings for specified category


        """
        pass

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
        training_files = glob.glob(self.scenario_path + f'/{TRAINING}/*.sc')
        val_files = glob.glob(self.scenario_path + f'/{VALIDATION}/*.sc')
        test_files = glob.glob(self.scenario_path + f'/{TEST}/*.sc')
        all_files = training_files + val_files + test_files
        for file in all_files:
            file_name = os.path.dirname(file)
            recording_type = get_type_of_recording(file)
            temp_dict = {
                'recording_type': recording_type,
                'sc_path': os.path.splitext(file)[0] + '.sc',
                'scap_path': file
            }
            if TRAINING in file_name:
                metadata_dict[TRAINING][get_file_name(file)] = temp_dict
            elif VALIDATION in file_name:
                metadata_dict[VALIDATION][get_file_name(file)] = temp_dict
            elif TEST in file_name:
                metadata_dict[TEST][get_file_name(file)] = temp_dict
        return metadata_dict

    def _check_and_convert_scap(self):
        """
            Check if sc files exist.
            If not convert all scap to sc.
        """


