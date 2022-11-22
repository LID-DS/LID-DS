import re
import json
from dataloader.dataloader_factory import dataloader_factory


def append_feature_dict(feature, dictionary: dict, key: str):
    if key not in dictionary:
        dictionary.update({key: feature})
    elif feature not in dictionary[key]:
        dictionary[key].append(feature)


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

    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")

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

                    append_feature_dict(syscall.user_id(), alert_analysis_dict, 'users')
                    append_feature_dict(syscall.process_name(), alert_analysis_dict, 'processes')
                    append_feature_dict(syscall.name(), alert_analysis_dict, 'syscall_names')

                    if 'fd' in syscall.params():
                        params_string = syscall.params()['fd']

                        ip_matches = re.findall(ip_pattern, params_string)
                        if ip_matches:
                            for ip in ip_matches:
                                append_feature_dict(ip, alert_analysis_dict, 'ip')

                        file_matches = re.findall(file_path_pattern, params_string)
                        if file_matches:
                            for file in file_matches:
                                append_feature_dict(file, alert_analysis_dict, 'files')

            print(alert_analysis_dict)
