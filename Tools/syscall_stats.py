import json
import argparse
import os
from tqdm import tqdm

from dataloader.data_loader import DataLoader, RecordingType
from dataloader.syscall import Direction

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
    with open(os.path.join(output_path, scenario_name + '_syscall_stats.json'), 'w') as jsonfile:
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


def calc_stats_for_recording_type(recording_list: list, description: str) -> dict:
    """

    calculates syscall statistics for one recording type represented as list of Recording Objects

    Returns:
        statistics as dictionary

    """
    syscall_distribution = {}
    open_syscall_count = 0
    close_syscall_count = 0
    recording_count = 0

    # stores list of numbers of distinct users, threads, and processes
    distinct_user_ids_count_list = []
    distinct_thread_ids_count_list = []
    distinct_process_ids_count_list = []

    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        recording_count += 1

        # initialization of empty sets to ensure distinction of thread_ids, process_ids and user_ids
        distinct_thread_ids = set([])
        distinct_process_ids = set([])
        distinct_user_ids = set([])

        for syscall in recording.syscalls():
            syscall_name = syscall.name()
            syscall_direction = syscall.direction()
            syscall_thread_id = syscall.thread_id()
            syscall_process_id = syscall.process_id()
            syscall_user_id = syscall.user_id()

            # fills and increments syscall distribution statistics
            if syscall_name in syscall_distribution.keys():
                syscall_distribution[syscall_name] += 1
            else:
                syscall_distribution[syscall_name] = 1

            # open and close syscalls are handled individually
            if syscall_direction == Direction.OPEN:
                open_syscall_count += 1
            else:
                close_syscall_count += 1

            # adding user_id, process_id and user_id to set if not yet existing
            distinct_thread_ids.add(syscall_thread_id)
            distinct_process_ids.add(syscall_process_id)
            distinct_user_ids.add(syscall_user_id)

        # adds recording paths to list if recording is empty
        if len(distinct_user_ids) == 0:
            append_to_textile(args.output_path, recording.path)

        """
        appending length of distinct sets to overview lists, represents the number of distinct users,
        processes and threads
        """
        distinct_user_ids_count_list.append(len(distinct_user_ids))
        distinct_thread_ids_count_list.append(len(distinct_thread_ids))
        distinct_process_ids_count_list.append(len(distinct_process_ids))

    recording_type_results = {

        'syscall_distribution': syscall_distribution,
        'open_syscall_count': open_syscall_count,
        'close_syscall_count': close_syscall_count,
        'average_open_syscall_count': open_syscall_count / recording_count if not recording_count == 0 else 0,
        'average_close_syscall_count': close_syscall_count / recording_count if not recording_count == 0 else 0,
        'average_distinct_processes': calc_average_from_list(distinct_process_ids_count_list,
                                                             recording_count),
        'average_distinct_users': calc_average_from_list(distinct_user_ids_count_list,
                                                         recording_count),
        'average_distinct_threads': calc_average_from_list(distinct_thread_ids_count_list,
                                                           recording_count)
    }

    return recording_type_results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

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
                record_results = calc_stats_for_recording_type(data_parts[data_part][recording_type], f"{scenario}: {data_part} - {recording_type}".rjust(45))
                if scenario not in result_dict.keys():
                    result_dict[scenario] = {}

                if data_part not in result_dict[scenario].keys():
                    result_dict[scenario][data_part] = {}

                result_dict[scenario][data_part][recording_type] = record_results

        # saving the result
        save_to_json(result_dict, args.output_path, scenario)
