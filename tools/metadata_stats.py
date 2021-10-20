import os
import json
import argparse

from tqdm import tqdm
from typing import Union

from dataloader.data_loader import DataLoader, RecordingType


"""
data format
{
    <scenario_name> {
        <dataset_part> {
            <recording_type> {
                recording_time: {
                    min: int,
                    max: int,
                    sum: int,
                    avg: float
                }
                normal_container: {
                    min: int,
                    max: int,
                    sum: int,
                    avg: float
                }
            }
        }
    }
}
"""


def save_to_json(results: dict, output_path: str, scenario_name: str):
    """

    saves results for one scenario to json file located at a given path
    overwrites old files

    """
    with open(os.path.join(output_path, scenario_name + '_metadata_stats.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def calc_stats_for_recording_type(recording_list: list, description: str):
    """

        calculates statsitic for whole recording_type

        Param:
        recording_list (list): list if Recordings

        Rerturns:
        dict: statistic of recording_type

    """
    result = {
        'recording_time': {
            'min': None,
            'max': 0,
            'sum': 0,
            'avg': 0
        },
        'normal_container': {
            'min': None,
            'max': 0,
            'sum': 0,
            'avg': 0
        }
    }
    recording_count = 0
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        recording_count += 1
        metadata = recording.metadata()
        recording_time = metadata['recording_time']
        normal_container = len(metadata['container'])
        result['recording_time'] = update_values(recording_time, result['recording_time'])
        result['normal_container'] = update_values(normal_container, result['normal_container'])
    result['recording_time'] = calc_avg(recording_count, result['recording_time'])
    result['normal_container'] = calc_avg(recording_count, result['normal_container'])
    return result


def update_values(current_value: Union[int, float], stats: dict) -> dict:
    """

        udpate min max and sum for a new entry in current stat

        Param:
        current_value (int, float): new entry to include in statistic
        stats (dict): statistic keeping track of previously seen entries

        Returns:
        dict: updated stats dictionary

    """
    if stats['min']:
        if current_value < stats['min']:
            stats['min'] = current_value
    else:
        stats['min'] = current_value
    if current_value > stats['max']:
        stats['max'] = current_value
    stats['sum'] += current_value
    return stats


def calc_avg(count: int, stats: dict) -> dict:
    """

        calculate avg value with count

        Param:
        count (int): count of recordings
        stats (dict): current stats

        Returns:
        dict: stats with avg entry

    """
    stats['avg'] = stats['sum'] / count
    return stats


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

    parser.add_argument('-d', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('-o', dest='output_path', action='store', type=str, required=True,
                        help='Output Path for statistics')

    args = parser.parse_args()

    scenario_names = os.listdir(args.base_path)
    # iterate through list of all scenarios
    for scenario in scenario_names:

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
                'Normal and Attack': dataloader.test_data(
                    recording_type=RecordingType.NORMAL_AND_ATTACK)
            }
        }

        # calc for Training, Validation and Test data
        for data_part in data_parts.keys():
            # calc for Idle, Normal, Attack and Normal and Attack
            for recording_type in data_parts[data_part].keys():
                record_result = calc_stats_for_recording_type(
                    data_parts[data_part][recording_type],
                    f'{scenario}: {data_part} - {recording_type}')
                if scenario not in result_dict.keys():
                    result_dict[scenario] = {}
                if data_part not in result_dict[scenario].keys():
                    result_dict[scenario][data_part] = {}
                result_dict[scenario][data_part][recording_type] = record_result
        save_to_json(result_dict, args.output_path, scenario)
