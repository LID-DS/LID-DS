import json
import argparse
import os

from tqdm import tqdm
from dataloader.data_loader import DataLoader, RecordingType

"""
data format
{
    <scenario_name> {
        <dataset_part> {
            <recording_type> {
                protocol_distribution {
                    <protocol_name>: xxx
                    <protocol_name>: xxx
                }
                http_method_distribution {
                    <method_name>: xxx
                    <method_name>: xxx
                }
                average_distinct_ips: xxx
                average_packet_count: xxx
            }
        }
    }
}
"""

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


def save_to_json(results: dict, output_path: str, scenario_name: str):
    """

    saves results for one scenario to json file located at a given path
    overwrites old files

    """
    with open(os.path.join(output_path, scenario_name + '_packets_stats.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def calc_average_from_list(lst: list, count: int) -> float:
    """

    calculates average over a given list
    additional count to ensure detection of fails in scenarios

    Returns:
        average over list as float

    """
    total = 0

    for z in lst:
        total += z

    return total / count if not count == 0 else 0


def calc_stats_for_recording_type(recording_list: list, description: str) -> dict:
    """

    calculates syscall statistics for one recording type represented as list of Recording Objects

    Returns:
        statistics as dictionary

    """

    protocol_distribution = {}
    http_method_distribution = {}
    distinct_ip_count_list = []
    package_count_list = []
    recording_count = 0

    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        recording_count += 1
        package_count = 0
        distinct_ip_addresses = set([])
        extraction = recording.packets()

        for packet in extraction.frame:
            package_count += 1

            # retrieves data for every sublayer of one packet, nonexistent values return None
            for layer in packet.layers:
                protocol = layer.layer_name
                ip = layer.get_field_value('src')
                http_method = layer.get_field_value('request_method')

                if protocol not in protocol_distribution.keys():
                    protocol_distribution[protocol] = 1
                else:
                    protocol_distribution[protocol] += 1

                if ip is not None:
                    distinct_ip_addresses.add(ip)

                if http_method is not None:
                    if http_method not in http_method_distribution.keys():
                        http_method_distribution[http_method] = 1
                    else:
                        http_method_distribution[http_method] += 1

        distinct_ip_count_list.append(len(distinct_ip_addresses))
        package_count_list.append(package_count)

    # joining the results
    recording_type_results = {
        'protocol_distribution': protocol_distribution,
        'http_method_distribution': http_method_distribution,
        'average_distinct_ips': calc_average_from_list(distinct_ip_count_list, recording_count),
        'average_package_count': calc_average_from_list(package_count_list, recording_count)
    }
    return recording_type_results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Packets')

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
                record_results = calc_stats_for_recording_type(data_parts[data_part][recording_type],
                                                               f"{scenario}: {data_part} - {recording_type}".rjust(45))
                if scenario not in result_dict.keys():
                    result_dict[scenario] = {}

                if data_part not in result_dict[scenario].keys():
                    result_dict[scenario][data_part] = {}

                result_dict[scenario][data_part][recording_type] = record_results

        # saving the result
        save_to_json(result_dict, args.output_path, scenario)
