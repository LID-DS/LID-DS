import json
import argparse
import os
from tqdm import tqdm

from dataloader.data_loader import DataLoader, RecordingType

SCENARIO_NAMES = [
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2014-0160",
    "CVE-2017-7529",
    "CVE-2017-12635_6",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "CVE-2020-9484",
    "CVE-2020-13942",
    "CVE-2020-23839",
    "CWE-89-SQL-injection",
    "EPS_CWE-434",
    "Juice-Shop",
    "PHP_CWE-434",
    "ZipSlip"
]


def save_to_json(results: dict, output_path: str):
    """

    saves results for one scenario to json file located at a given path
    overwrites old files

    """
    with open(os.path.join(output_path, 'empty_recordings.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def append_to_textile(output_path: str, line: str):
    """

    creates a text file for empty records if it does not exist yet
    then appends new lines to it

    """
    filepath = os.path.join(output_path, 'empty_records.txt')
    if not os.path.exists(filepath):
        open(filepath, 'w+')

    with open(filepath, 'a') as textfile:
        textfile.write(line + '\n')


def find_empty_recordings(recording_list: list, description: str):
    """

    looks for empty recordings by trying to get oen syscall from syscall generator, if it fails the recording is empty

    """

    empty_recording_list = []
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        generator = recording.syscalls()
        try:
            syscall = next(generator)
        except:
            # calculates index based on position of LID-DS directory in file path
            path_parts = recording.path.split('/')
            index = len(path_parts) - path_parts.index('LID-DS-2021') - 1

            empty_recording_list.append(os.path.join(*path_parts[-index:]))

    return empty_recording_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detection Tool to find empty records in LID-DS 2021')

    parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('-o', dest='output_path', action='store', type=str, required=True,
                        help='Output Path for statistics')

    args = parser.parse_args()

    result_dict = {}

    # iterates through list of all scenarios, main loop
    for scenario in SCENARIO_NAMES:

        scenario_path = os.path.join(args.base_path, scenario)
        dataloader = DataLoader(scenario_path)

        # dict to describe dataset structure
        data_parts = {
            'Training': {
                'Idle': dataloader.training_data(recording_type=RecordingType.IDLE),
                'Normal': dataloader.training_data(recording_type=RecordingType.NORMAL)
            },
            'Validation': {
                'Idle': dataloader.validation_data(recording_type=RecordingType.IDLE),
                'Normal': dataloader.validation_data(recording_type=RecordingType.NORMAL)
            },
            'Test': {
                'Idle': dataloader.test_data(recording_type=RecordingType.IDLE),
                'Normal': dataloader.test_data(recording_type=RecordingType.NORMAL),
                'Attack': dataloader.test_data(recording_type=RecordingType.ATTACK),
                'Normal and Attack': dataloader.test_data(recording_type=RecordingType.NORMAL_AND_ATTACK)
            }
        }

        # runs calculation for every recording type of every data part in data_part dictionary
        for data_part in data_parts.keys():
            for recording_type in data_parts[data_part].keys():
                result = find_empty_recordings(data_parts[data_part][recording_type],
                                               f"{scenario}: {data_part} - {recording_type}".rjust(45))

                if scenario not in result_dict.keys():
                    result_dict[scenario] = {}

                if data_part not in result_dict[scenario].keys():
                    result_dict[scenario][data_part] = {}

                result_dict[scenario][data_part][recording_type] = result

    save_to_json(result_dict, args.output_path)
