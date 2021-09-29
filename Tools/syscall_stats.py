import json
import argparse
import os
from tqdm import tqdm

from Tools.data_loader import DataLoader, RecordingType
from Tools.syscall import Direction

SCENARIO_NAMES = [
    "Bruteforce_CWE-307",  # 0
    "CVE-2012-2122",  # 1
    "CVE-2014-0160",  # 2
    "CVE-2017-7529",  # 3
    "CVE-2018-3760",  # 4
    "CVE-2019-5418",  # 5
    "EPS_CWE-434",  # 6
    "PHP_CWE-434",  # 7
    "SQL_Injection_CWE-89",  # 8
    "ZipSlip"  # 9
]


def save_to_json(results):
    with open('Tools/syscall_stats.json', 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def calc_average_from_list(lst, count):
    total = 0

    for z in lst:
        total += z
    return total / count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

    parser.add_argument('-p', dest='base_path', action='store', type=str, required=True,
                        help='LID-DS Base Path')

    args = parser.parse_args()

    result_dict = {}

    for scenario in tqdm(SCENARIO_NAMES[3:4], desc='Calculating Statistics'):

        scenario_path = os.path.join(args.base_path, scenario)
        dataloader = DataLoader(scenario_path)

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

        for data_part in data_parts.keys():
            for recording_type in data_parts[data_part].keys():

                syscall_distribution = {}
                open_syscall_count = 0
                close_syscall_count = 0
                recording_count = 0

                distinct_user_ids_count_list = []
                distinct_thread_ids_count_list = []
                distinct_process_ids_count_list = []

                for recording in data_parts[data_part][recording_type]:
                    recording_count += 1
                    distinct_thread_ids = set([])
                    distinct_process_ids = set([])
                    distinct_user_ids = set([])

                    for syscall in recording.syscalls():
                        syscall_name = syscall.name()
                        syscall_direction = syscall.direction()
                        syscall_thread_id = syscall.thread_id()
                        syscall_process_id = syscall.process_id()
                        syscall_user_id = syscall.user_id()

                        if syscall_name in syscall_distribution.keys():
                            syscall_distribution[syscall_name] += 1
                        else:
                            syscall_distribution[syscall_name] = 1

                        if syscall_direction == Direction.OPEN:
                            open_syscall_count += 1
                        else:
                            close_syscall_count += 1

                        distinct_thread_ids.add(syscall_thread_id)
                        distinct_process_ids.add(syscall_process_id)
                        distinct_user_ids.add(syscall_user_id)

                    distinct_user_ids_count_list.append(len(distinct_user_ids))
                    distinct_thread_ids_count_list.append(len(distinct_thread_ids))
                    distinct_process_ids_count_list.append(len(distinct_process_ids))

                if scenario not in result_dict.keys():
                    result_dict[scenario] = {}

                if data_part not in result_dict[scenario].keys():
                    result_dict[scenario][data_part] = {}


                result_dict[scenario][data_part][recording_type] = {
                    'syscall_distribution': syscall_distribution,
                    'open_syscall_count': open_syscall_count,
                    'close_syscall_count': close_syscall_count,
                    'average_open_syscall_count': open_syscall_count / recording_count,
                    'average_close_syscall_count': close_syscall_count / recording_count,
                    'average_distinct_processes': calc_average_from_list(distinct_process_ids_count_list,
                                                                         recording_count),
                    'average_distinct_users': calc_average_from_list(distinct_user_ids_count_list,
                                                                     recording_count),
                    'average_distinct_threads': calc_average_from_list(distinct_thread_ids_count_list,
                                                                       recording_count)
                }

    save_to_json(result_dict)

"""

data format

{
    <scenario_name> {
        <dataset_part> {
            <recording_type> {
                syscall_distribution {
                    <syscall_name>: xxx
                    <syscall_name>: xxx
                }
                open_syscall_count: xxx
                close_syscall_count: xxx
                average_syscall_count: xxx
                average_distinct_processes: xx
                average_distinct_threads: xx
                average_user_count: xx
            }
        }
    }
}
"""
