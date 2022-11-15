import json
import zipfile
from dataloader.dataloader_factory import dataloader_factory

data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
# scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/Bruteforce_CWE-307'

# dataloader = dataloader_factory(scenario_path)


# for recording in dataloader.test_data():
#     for syscall in recording.syscalls():
#         print(syscall.name())


alert_file = open(alert_file_path)
alert_dict = json.load(alert_file)

# iterating through alert entries in input alert file
for entry in alert_dict['alarms']:
    # extracting information from json
    first_line_id = entry['first_line_id']
    last_line_id = entry['last_line_id']
    first_timestamp = entry['first_timestamp']
    last_timestamp = entry['last_timestamp']
    scenario_path = entry['filepath']

    syscalls_in_alert = last_line_id - first_line_id
    time_window_seconds = (last_timestamp - first_timestamp) * pow(10, -9)

    # initialize dict for alert
    alert_analysis_dict = {'scenario_path': scenario_path, 'syscalls_in_alert': syscalls_in_alert,
                           'time_window': time_window_seconds, 'users': [], 'processes': [], 'syscall_names': []}

    archive = zipfile.ZipFile(data_base + '/' + scenario_path, 'r')
    syscall_file = archive.namelist()[1]
    with archive.open(str(syscall_file)) as syscalls:
        for line_id, syscall in enumerate(syscalls, start=1):
            syscall_line = syscall.decode('utf-8').rstrip()
            if line_id in range(first_line_id, last_line_id + 1):
                print(line_id, syscall_line)

                user = syscall_line.split(' ')[1]
                process_name = syscall_line.split(' ')[3]
                syscall_name = syscall_line.split(' ')[5]
                if user not in alert_analysis_dict['users']:
                    alert_analysis_dict['users'].append(user)

                if process_name not in alert_analysis_dict['processes']:
                    alert_analysis_dict['processes'].append(process_name)

                if syscall_name not in alert_analysis_dict['syscall_names']:
                    alert_analysis_dict['syscall_names'].append(syscall_name)


