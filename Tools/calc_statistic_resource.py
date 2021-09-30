import json
from typing import Union

from Tools.data_loader import DataLoader
from Tools.data_loader import get_type_of_recording
from Tools.data_loader import RecordingType


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

stats_per_scenario = {
    "Bruteforce_CWE-307": {},
    "CVE-2012-2122": {},
    "CVE-2014-0160": {},
    "CVE-2017-7529": {},
    "CVE-2017-12635_6": {},
    "CVE-2018-3760": {},
    "CVE-2019-5418": {},
    "CVE-2020-9484": {},
    "CVE-2020-13942": {},
    "CVE-2020-23839": {},
    "CWE-89-SQL-Injection": {},
    "EPS_CWE-434": {},
    "Juice-Shop": {},
    "PHP_CWE-434": {},
    "ZipSlip": {}
}


def update_stat_single(current: Union[int, float], stat: dict) -> dict:
    """

        receives current value and updates min max and avg

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


def set_default_stat():
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


def stats_per_category(data, category: str, stats_per_category: dict) -> dict:
    stats_recording = set_default_stat()
    if category == 'test':
        tmp_dict = {
            'ATTACK': [],
            'IDLE': [],
            'NORMAL': [],
            'NORMAL_AND_ATTACK': []
        }
    else:
        tmp_dict = {
            'IDLE': [],
            'NORMAL': [],
        }
    for recording in data:
        entry_counter = 0
        recording_type = get_type_of_recording(recording.metadata())
        if recording_type == RecordingType.ATTACK:
            recording_type = 'ATTACK'
        if recording_type == RecordingType.IDLE:
            recording_type = 'IDLE'
        if recording_type == RecordingType.NORMAL:
            recording_type = 'NORMAL'
        if recording_type == RecordingType.NORMAL_AND_ATTACK:
            recording_type = 'NORMAL_AND_ATTACK'
        for resource in recording.resource_stats():
            stats_recording = update_stat(stats_recording,
                                          resource)
            entry_counter += 1
        for value in ['cpu_usage',
                      'network_send',
                      'network_received',
                      'storage_read',
                      'storage_written']:
            stats_recording[value]['avg'] = stats_recording[value]['sum'] / entry_counter
        tmp_dict[recording_type].append(stats_recording)
        stats_recording = set_default_stat()
    return tmp_dict


def calc_avg(counter: int, stats_recording: dict) -> dict:
    for entry in stats_recording.keys():
        stats_recording[entry]['avg'] = stats_recording[entry]['sum'] / counter
    return stats_recording


def full_type_analysis(recording: dict, recording_type_dict: dict) -> dict:
    for value in ['cpu_usage',
                  'network_send',
                  'network_received',
                  'storage_read',
                  'storage_written']:
        if recording_type_dict[value]['min']:
            if recording[value]['min'] < recording_type_dict['cpu_usage']['min']:
                recording_type_dict[value]['min'] = recording['cpu_usage']['min']
        else:
            recording_type_dict[value]['min'] = recording[value]['min']
        if recording[value]['max'] > recording_type_dict[value]['max']:
            recording_type_dict[value]['max'] = recording[value]['max']
        recording_type_dict[value]['sum'] += recording[value]['avg']

    return recording_type_dict


def calc_result_statistic(stats: dict) -> dict:
    for scenario in stats:
        result_dict = {
            'training': {},
            'validation': {},
            'test': {},
        }
        for category in stats[scenario]:
            recording_type_dict = set_default_stat()
            for recording_type in stats[scenario][category]:
                counter = 0
                for recording in stats[scenario][category][recording_type]:
                    counter += 1
                    recording_type_dict = full_type_analysis(recording, recording_type_dict)
                for value in ['cpu_usage',
                              'network_send',
                              'network_received',
                              'storage_read',
                              'storage_written']:
                    recording_type_dict[value]['avg'] = recording_type_dict[value]['sum'] / counter
                result_dict[category][recording_type] = recording_type_dict
        with open(f'Resource_statistics/{scenario}.json', 'w') as file:
            json.dump(result_dict, file)
    return result_dict


if __name__ == '__main__':

    for scenario in SCENARIO_NAMES:
        dataloader = DataLoader('../../Dataset/{scenario}')
        training_data = dataloader.training_data()
        stats_per_scenario[scenario]['training'] = \
            stats_per_category(data=training_data,
                               category='training',
                               stats_per_category=stats_per_scenario[scenario])
        validation_data = dataloader.validation_data()
        stats_per_scenario[scenario]['validation'] = \
            stats_per_category(data=validation_data,
                               category='validation',
                               stats_per_category=stats_per_scenario[scenario])
        test_data = dataloader.test_data()
        stats_per_scenario[scenario]['test'] = \
            stats_per_category(data=test_data,
                               category='test',
                               stats_per_category=stats_per_scenario[scenario])
    result_dict = {}
    result_dict = calc_result_statistic(stats_per_scenario)
