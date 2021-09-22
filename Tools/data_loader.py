import os
import glob
import json
import zipfile
from enum import Enum
from recording import Recording

TRAINING = 'training'
VALIDATION = 'validation'
TEST = 'test'


def get_file_name(path):
    return os.path.splitext(os.path.basename(path))[0]


class RecordingType(Enum):
    NORMAL = 1
    NORMAL_AND_ATTACK = 2
    ATTACK = 3
    IDLE = 4


class DataLoader:
    """

        Recieves path of scenario

    """

    def __init__(self, scenario_path):
        """

            Save path of scenario

        """
        self.scenario_path = scenario_path
        self.metadata_list = self.collect_metadata()

    def training_data(self, recording_type: RecordingType = None) -> list:
        """

            Return list of recordings contained in training data
            Specify recordings with recording_type
            default: all included

        """
        recordings = self.extract_recordings(category=TRAINING,
                                             recording_type=recording_type)
        return recordings

    def validation_data(self, recording_type: RecordingType = None) -> list:
        """

            Return list of recordings contained in validation data
            Exclude specific recordings with recording_type

        """
        recordings = self.extract_recordings(category=VALIDATION,
                                             recording_type=recording_type)
        return recordings

    def test_data(self, recording_type: RecordingType = None) -> list:
        """

            Return list of recordings contained in test data
            Exclude specific recordings with recording_type

        """
        recordings = self.extract_recordings(category=TEST,
                                             recording_type=recording_type)
        return recordings

    def extract_recordings(self,
                           category: str,
                           recording_type: RecordingType = None) -> list:
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
                Category of recording : training, validataion, test
                    Name of recording
                    recording type

            :returns metadata_dict containing type of recording for every file

        """
        metadata_dict = {
            'training': {},
            'validation': {},
            'test': {}
        }
        training_files = glob.glob(self.scenario_path + '/training/*.zip')
        val_files = glob.glob(self.scenario_path + '/validation/*.zip')
        test_files = glob.glob(self.scenario_path + '/test/*/*.zip')
        all_files = training_files + val_files + test_files
        for file in all_files:
            with zipfile.ZipFile(file, 'r') as zip_ref:
                # remove zip extension and create json file name
                json_file_name = get_file_name(file) + '.json'
                with zip_ref.open(json_file_name) as unzipped:
                    unzipped_byte_json = unzipped.read()
                    # TODO remove replace?
                    unzipped_json = json.loads(unzipped_byte_json.decode('utf8').replace("'", '"'))
                    recording_type = self.get_type_of_recording(unzipped_json)
                    temp_dict = {
                        'recording_type': recording_type,
                        'path': file
                    }
                    if TRAINING in os.path.dirname(file):
                        metadata_dict['training'][get_file_name(file)] = temp_dict
                    elif VALIDATION in os.path.dirname(file):
                        metadata_dict['validation'][get_file_name(file)] = temp_dict
                    elif TEST in os.path.dirname(file):
                        metadata_dict['test'][get_file_name(file)] = temp_dict
                    else:
                        # TODO Fehlermeldung
                        pass
        return metadata_dict

    def get_type_of_recording(self, json_file_name: str) -> RecordingType:
        data = json_file_name

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


if __name__ == "__main__":
    dataloader = DataLoader('Bruteforce')
    training_data = dataloader.training_data()
    i = 0
    for recording in training_data:
        recording.packets()
        for syscall in recording.syscalls():
            i = i + 1  # print(syscall)
        break
