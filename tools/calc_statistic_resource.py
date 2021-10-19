import os
import json
from tqdm import tqdm
import argparse
from typing import Union

from dataloader.data_loader import DataLoader
from dataloader.data_loader import RecordingType

"""
{
    <scenario_name> {
        <dataset_part> {
            <recording_type> {
                cpu_usage: float,
                memory_usage: float,
                network_send: int,
                network_received: int,
                storage_read: int,
                storage_written: int

        }
    }
}
"""


def save_to_json(results: dict, output_path: str, scenario_name: str):
    """
    saves results for one scenario to json file located at a given path
    overwrites old files
    """
    with open(os.path.join(output_path, scenario_name + '_res_stats.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def update_stat_single(current: Union[int, float], stat: dict) -> dict:
    """

        receives current value and updates min max and avg of specific statistic of resources

        Param:
        current (int, float): current value for specific resource
        stat (dict): statistic of previous resource

        Returns:
        dict: updated statistic of resource

    """
    if stat['min']:
        if current < stat['min']:
            stat['min'] = current
    else:
        stat['min'] = current
    if current > stat['max']:
        stat['max'] = current
    stat['sum'] = stat['sum'] + current
    return stat


def update_stat(stats_recording: dict, resource: Union[int, float]) -> dict:
    """

        update current statstic of resources of single recording (stats_recording)
        with entry of resource

        Param:
        stats_recording (dict): current statistic of single recording
        resource (int, float): current resource entry for timestamp

        Returns:
        dict: updated statistic of single recording

    """
    stats_recording['cpu_usage'] = update_stat_single(current=resource.cpu_usage(),
                                                      stat=stats_recording['cpu_usage'])
    stats_recording['memory_usage'] = update_stat_single(current=resource.memory_usage(),
                                                         stat=stats_recording['memory_usage'])
    stats_recording['network_received'] = update_stat_single(resource.network_received(),
                                                             stats_recording['network_received'])
    stats_recording['network_send'] = update_stat_single(current=resource.network_send(),
                                                         stat=stats_recording['network_send'])
    stats_recording['storage_read'] = update_stat_single(current=resource.storage_read(),
                                                         stat=stats_recording['storage_read'])
    stats_recording['storage_written'] = update_stat_single(current=resource.storage_written(),
                                                            stat=stats_recording['storage_written'])
    return stats_recording


def set_default_stat() -> dict:
    """

        helper function to set specific initial values

        Returns:
        dict: with set initial values

    """
    stats_recording = {
        'cpu_usage': {
            'min': None,
            'max': 0.0,
            'sum': 0.0,
            'avg': 0.0
        },
        'memory_usage': {
            'min': None,
            'max': 0,
            'sum': 0.0,
            'avg': 0.0
        },
        'network_received': {
            'min': None,
            'max': 0,
            'sum': 0.0,
            'avg': 0.0
        },
        'network_send': {
            'min': None,
            'max': 0,
            'sum': 0.0,
            'avg': 0.0
        },
        'storage_read': {
            'min': None,
            'max': 0,
            'sum': 0.0,
            'avg': 0.0
        },
        'storage_written': {
            'min': 0,
            'max': 0,
            'sum': 0.0,
            'avg': 0.0
        }
    }
    return stats_recording


def calc_stats_for_recording_type(recording_list: list, description) -> dict:
    """

        calculates statsitic for whole recording_type

        Param:
        recording_list (list): list if Recordings

        Rerturns:
        dict: statistic of recording_type

    """
    # calc for every recording
    resources_per_recording = []
    for recording in tqdm(recording_list, description, unit=' recordings', smoothing=0):
        stats_recording = set_default_stat()
        entry_counter = 0
        # calc statistic for every resource in recording
        for resource in recording.resource_stats():
            stats_recording = update_stat(stats_recording,
                                          resource)
            entry_counter += 1
        # calc avg value for recording
        for entry in stats_recording.keys():
            stats_recording[entry]['avg'] = stats_recording[entry]['sum'] / entry_counter
        resources_per_recording.append(stats_recording)
    recording_type_stats = calc_stats_recording(resources_per_recording)
    return recording_type_stats


def calc_stats_recording(recordings: list) -> dict:
    """

        receives a list of statistic of recordings
        and creates statistic of whole list

        Param:
        recordings (list): list of statistic of recordings

        Returns:
        dict: statistic of list


    """
    stats = set_default_stat()
    for recording in recordings:
        for value in recording.keys():
            stats[value] = update_list_entry(recording[value], stats[value])
    for entry in stats.keys():
        stats[entry]['avg'] = stats[entry]['sum'] / len(recordings)
        del stats[entry]['sum']
    return stats


def update_list_entry(current_stat: dict, stats: dict) -> dict:
    """

        udpate min max and sum for a new entry in current stat

        Param:
        current_stat (dict): new entry to include in statistic
        stats (dict): statistic keeping track of previously seen entries

        Returns:
        dict: updated stats dictionary

    """
    if stats['min'] is None:
        stats['min'] = current_stat['min']
    elif current_stat['min'] < stats['min']:
        stats['min'] = current_stat['min']
    if current_stat['max'] > stats['max']:
        stats['max'] = current_stat['max']
    stats['sum'] = stats['sum'] + current_stat['avg']
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
