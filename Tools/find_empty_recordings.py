import json
import argparse
import os
from tqdm import tqdm

from Tools.data_loader import DataLoader, RecordingType
from Tools.syscall import Direction

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
    "CWE-89-SQL-Injection",
    "EPS_CWE-434",
    "Juice-Shop",
    "PHP_CWE-434",
    "ZipSlip"
]


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

    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        generator = recording.syscalls()
        try:
            syscall = next(generator)
        except:
            append_to_textile(args.output_path, recording.path[37:])





if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detection Tool to find empty records in LID-DS 2021')

    parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('-o', dest='output_path', action='store', type=str, required=True,
                        help='Output Path for statistics')

    args = parser.parse_args()

    # iterates through list of all scenarios, main loop
    for scenario in SCENARIO_NAMES:
        result_dict = {}

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
                find_empty_recordings(data_parts[data_part][recording_type], f"{scenario}: {data_part} - {recording_type}".rjust(45))

