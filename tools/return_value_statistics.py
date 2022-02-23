from dataloader.recording_2019 import RecordingDataParts
from dataloader.syscall import Direction
from dataloader.dataloader_factory import dataloader_factory


import matplotlib.pyplot as plt
import pandas as pd

from brokenaxes import brokenaxes
from tqdm import tqdm


import json
import os

from enum import IntEnum


class Plot(IntEnum):
    WRITE = 1
    READ = 2
    SOCKET_SEND = 3
    SOCKET_RECV = 4
    DENTS = 5


def save_to_json(results: dict, scenario_name: str):
    """

    saves results for one scenario to json file located at a given path
    overwrites old files

    """
    with open(os.path.join(scenario_name + '_syscall_stats.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def calc_return_value_stats(recording_list, description):
    normal_count = 0
    exploit_count = 0
    result_dict = {
        'normal': {
            'written': [],
            'read': [],
            'socket_send': [],
            'socket_recv': [],
            'dents': []
        },
        'exploit': {
            'written': [],
            'read': [],
            'socket_send': [],
            'socket_recv': [],
            'dents': []
        }
    }
    write = ['pwrite', 'write', 'writev']
    read = ['pread', 'read', 'readv']
    send_socket = ['sendfile', 'sendmsg']
    recv_socket =  ['recvfrom', 'recv', 'recvmsg']
    get_dents =  ['getdents']
    not_interesting = ['clone', 'getcwd', 'lseek', 'fcntl', 'futex', 'epoll_wait']
    error_codes = ['EAGAIN', 'EINVAL', 'ECONNRESET']
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        if recording.recording_data_list[RecordingDataParts.IS_EXECUTING_EXPLOIT] == 'True':
            exploit_count += 1
            rec = 'exploit'
        else:
            normal_count += 1
            rec = 'normal'
        for syscall in recording.syscalls():
            return_value_string = syscall.param('res')
            if return_value_string:
                try:
                    return_value_int = int(return_value_string)
                    if return_value_int > 10 and return_value_int < 10000000000:
                        if syscall.name() in write:
                            result_dict[rec]['written'].append(return_value_int)
                        elif syscall.name() in read:
                            result_dict[rec]['read'].append(return_value_int)
                        elif syscall.name() in send_socket:
                            result_dict[rec]['socket_send'].append(return_value_int)
                        elif syscall.name() in recv_socket:
                            result_dict[rec]['socket_recv'].append(return_value_int)
                        elif syscall.name() in get_dents:
                            result_dict[rec]['dents'].append(return_value_int)
                        elif syscall.name() in not_interesting:
                            pass
                        else:
                            print(syscall.name(), return_value_int)
                except ValueError:
                    if any(error in return_value_string for error in error_codes):
                        # error code was returned so ValueError is expected
                        # in extraction -1 is returned
                        pass
    return result_dict


if __name__ == '__main__':

    SCENARIO_NAMES = [
        # "Bruteforce_CWE-307",
        # "CVE-2012-2122",
        # "CVE-2014-0160"
        "CVE-2017-7529",
        # "CVE-2018-3760",
        # "CVE-2019-5418",
        # "PHP_CWE-434",
        # "EPS_CWE-434",
        # "ZipSlip"
    ]
    # iterates through list of all scenarios, main loop
    for scenario in SCENARIO_NAMES:
        # scenario = 'CVE-2017-7529'
        dataloader = dataloader_factory(f'../../Dataset/{scenario}/', Direction.CLOSE)
        result_dict = {}

        # dict to describe dataset structure
        data_parts = {
            # 'Training': dataloader.training_data()
            # 'Validation': dataloader.validation_data(),
            'Test': dataloader.test_data()
        }
        for data_part in data_parts.keys():
            record_results = calc_return_value_stats(data_parts[data_part], f"{scenario}: {data_part}".rjust(45))
            if scenario not in result_dict.keys():
                result_dict[scenario] = {}
            result_dict[scenario][data_part] = record_results

        data_dict = {
            'written': [],
            'read': [],
            'socket_send': [],
            'socket_recv': [],
            'dents': []
        }
        for scenario in result_dict.keys():
            for rec_type in result_dict[scenario]['Test'].keys():
                for byte_type in result_dict[scenario]['Test'][rec_type].keys():
                    data_dict[byte_type].append(pd.DataFrame(result_dict[scenario]['Test'][rec_type][byte_type]))
        for entry in data_dict:
            df_normal = data_dict[entry][0]
            df_exploit = data_dict[entry][1]
            ax1 = plt.subplot(211)
            plt.title(f'{entry} - System Calls')
            ax1.hist(df_normal, color='#076678')
            ax1.legend(['Normalverhalten'], loc='upper right')
            ax1.set_ylabel('Occurences')
            ax2 = plt.subplot(212, sharex=ax1)
            ax2.hist(df_exploit, color='#9d0006')
            ax2.legend(['Normal- und Angriffsverhalten'], loc='upper right')
            ax2.set_ylabel('Occurences')
            ax2.set_xlabel('Bytes')
            plt.savefig(f'images/fix{scenario}{entry}.jpg', dpi=200)
            plt.figure()
        # plot.show()
        #fig = px.histogram(df)
        # fig.wirte_image('images/test_img.svg')
        #fig.show()
        #save_to_json(result_dict, scenario)
