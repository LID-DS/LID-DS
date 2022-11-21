import re
import json
from dataloader.dataloader_factory import dataloader_factory

# data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
# alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'
dataloader = dataloader_factory(scenario_path)

alert_file = open(alert_file_path)
alert_dict = json.load(alert_file)

# iterating through alert entries in input alert file
for entry in alert_dict['alarms']:
    first_line_id = entry['first_line_id']
    last_line_id = entry['last_line_id']
    first_timestamp = entry['first_timestamp']
    last_timestamp = entry['last_timestamp']
    scenario_path = entry['filepath']
    recording_alert = scenario_path.strip("/'").split('/')[3].strip(".zip")

    syscalls_in_alert = last_line_id - first_line_id
    time_window_seconds = (last_timestamp - first_timestamp) * pow(10, -9)

    ip_pattern = re.compile("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$")
    file_path_pattern = re.compile("^/|(/[a-zA-Z0-9_-]+)+$")

    # initialize dict for alert
    alert_analysis_dict = {'scenario_path': scenario_path,
                           'syscalls_in_alert': syscalls_in_alert,
                           'time_window': time_window_seconds,
                           'users': [],
                           'processes': [],
                           'syscall_names': [],
                           'files': [],
                           'ip': []}

    for recording in dataloader.test_data():
        if recording.name == recording_alert:
            for syscall in recording.syscalls():
                if syscall.line_id in range(first_line_id, last_line_id + 1):

                    if syscall.user_id() not in alert_analysis_dict['users']:
                        alert_analysis_dict['users'].append(syscall.user_id())

                    if syscall.process_name() not in alert_analysis_dict['processes']:
                        alert_analysis_dict['processes'].append(syscall.process_name())

                    if syscall.name() not in alert_analysis_dict['syscall_names']:
                        alert_analysis_dict['syscall_names'].append(syscall.name())

                    if 'fd' in syscall.params():
                        print(syscall.params()['fd'])
                        if re.search(file_path_pattern, syscall.params()['fd']):
                            file = re.search(file_path_pattern, syscall.params()['fd'])
                            alert_analysis_dict['files'].append(file)
                        if re.search(ip_pattern, syscall.params()['fd']):
                            ip = re.search(ip_pattern, syscall.params()['fd'])
                            alert_analysis_dict['ip'].append(ip)

                    # print(syscall.params())

            print(alert_analysis_dict)
