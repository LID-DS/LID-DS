import os
import glob
import json
import errno
import zipfile
import nest_asyncio

from enum import Enum
from dataloader.recording import Recording

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

    normal_behavoiur = False
    exploit = False

    # check for normal behaviour:
    for container in data["container"]:
        if container["role"] == "normal":
            normal_behavoiur = True
            break
    # check for exploit
    if data["exploit"]:
        exploit = True

    if normal_behavoiur is False and exploit is False:
        return RecordingType.IDLE
    if normal_behavoiur is False and exploit is True:
        return RecordingType.ATTACK
    if normal_behavoiur is True and exploit is False:
        return RecordingType.NORMAL
    if normal_behavoiur is True and exploit is True:
        return RecordingType.NORMAL_AND_ATTACK


class DataLoader:
    """

        Recieves path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self, scenario_path):
        """

            Save path of scenario and create metadata_list.

            Parameter:
            scenario_path (str): path of assosiated folder

        """
        if os.path.isdir(scenario_path):
            self.scenario_path = scenario_path
            self.metadata_list = self.collect_metadata()
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
        file_list = sorted(self.metadata_list[category].keys())
        for file in file_list:
            # check filter
            if recording_type:
                if self.metadata_list[category][file]['recording_type'] == recording_type:
                    recordings.append(Recording(name=file,
                                                path=self.metadata_list[category][file]['path']))
            else:
                recordings.append(Recording(name=file,
                                            path=self.metadata_list[category][file]['path']))
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


if __name__ == "__main__":
    base_path = '../../Dataset/'
    scenario_names = os.listdir(base_path)
    for scenario in scenario_names:
        print(scenario)
        dataloader = DataLoader(base_path + scenario)
        function_list = [dataloader.training_data,
                         dataloader.validation_data,
                         dataloader.test_data]
        for f in function_list:
            data = f()
            from tqdm import tqdm
            for recording in tqdm(data):
                pass
