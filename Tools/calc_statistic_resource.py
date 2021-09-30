from typing import Union

from Tools.data_loader import DataLoader


SCENARIO_NAMES = [
    "Bruteforce_CWE-307",       # 0
    "CVE-2012-2122",            # 1
    "CVE-2014-0160",            # 2
    "CVE-2017-7529",            # 3
    "CVE-2018-3760",            # 4
    "CVE-2019-5418",            # 5
    "EPS_CWE-434",              # 6
    "PHP_CWE-434",              # 7
    "SQL_Injection_CWE-89",     # 8
    "ZipSlip"                   # 9
]

stats_per_scenario = {
    "Bruteforce_CWE-307": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "CVE-2012-2122": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "CVE-2014-0160": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "CVE-2017-7529": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "CVE-2018-3760": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "CVE-2019-5418": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "EPS_CWE-434": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "PHP_CWE-434": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "SQL_Injection_CWE-89": {
        "training": {},
        "validation": {},
        "test": {}
    },
    "ZipSlip": {
        "training": {},
        "validation": {},
        "test": {}
    }
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
    for recording in data:
        entry_counter = 0
        for resource in recording.resource_stats():
            stats_recording = update_stat(stats_recording,
                                          resource)
            entry_counter += 1
        stats_recording = calc_avg(entry_counter, stats_recording)
        stats_per_category[category].append(stats_recording)
        stats_recording = set_default_stat()
    return stats_per_scenario


def calc_avg(counter: int, stats_recording: dict) -> dict:
    for entry in stats_recording.keys():
        stats_recording[entry]['avg'] = stats_recording[entry]['sum'] / counter
    return stats_recording


if __name__ == '__main__':

    dataloader = DataLoader('../../Dataset/Bruteforce')
    for scenario in SCENARIO_NAMES:
        training_data = dataloader.training_data()
        stats_per_scenario = stats_per_category(data=training_data,
                                                category='training',
                                                stats_per_category=stats_per_scenario[scenario])
        validation_data = dataloader.validation_data()
        stats_per_scenario = stats_per_category(data=validation_data,
                                                category='validation',
                                                stats_per_category=stats_per_scenario[scenario])
        test_data = dataloader.test_data()
        stats_per_scenario = stats_per_category(data=test_data,
                                                category='test',
                                                stats_per_category=stats_per_scenario[scenario])
        break
    print(stats_per_scenario[SCENARIO_NAMES[0]]['training'][0])
    result_dict = {}
