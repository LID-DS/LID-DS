import re
import json
import pprint
from dataloader.dataloader_factory import dataloader_factory

ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")


class Alert:
    def __init__(self, ds_path, time_window, syscall_count):
        self.path = ds_path
        self.time_window = time_window
        self.syscall_count = syscall_count
        self.process_list = []

    class Process:
        def __init__(self, process_id, user_id, process_name):
            self.process_id = process_id
            self.user_id = user_id
            self.process_name = process_name
            self.network_list = []
            self.files_list = []


# data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
# alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'
# scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'
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
    time_window_seconds = (last_timestamp - first_timestamp) * pow(10, -9)
    syscalls_in_alert = last_line_id - first_line_id

    alert = Alert(scenario_path, time_window_seconds, syscalls_in_alert)

    for recording in dataloader.test_data():
        if recording.name == recording_alert:
            for syscall in recording.syscalls():
                if syscall.line_id in range(first_line_id, last_line_id + 1):

                    existing_process = False

                    if alert.process_list:
                        for process in alert.process_list:
                            if syscall.process_id() not in process.values():
                                new_process_inst = alert.Process(syscall.process_id(), syscall.user_id(),
                                                                 syscall.process_name())
                                alert.process_list.append(vars(new_process_inst))

                            elif syscall.process_id() in process.values():
                                existing_process = True

                    else:
                        new_process_inst = alert.Process(syscall.process_id(), syscall.user_id(),
                                                         syscall.process_name())
                        alert.process_list.append(vars(new_process_inst))

                    if 'fd' in syscall.params() or 'out_fd' in syscall.params():
                        try:
                            fd_string = syscall.params()['fd']
                        except:
                            try:
                                connection_str = syscall.params()['out_fd']
                                file_str = syscall.params()['in_fd']
                            except:
                                print("No fd to match.")

                        if existing_process:
                            for process_entry in alert.process_list:
                                if process_entry['process_id'] == syscall.process_id():
                                    try:
                                        file_matches = re.findall(file_path_pattern, fd_string)
                                    except:
                                        file_matches = re.findall(file_path_pattern, file_str)

                                    if file_matches:
                                        for file in file_matches:
                                            file_dict = {'path': file,
                                                         'action': syscall.name()}
                                            if file_dict not in process_entry['files_list']:
                                                process_entry['files_list'].append(file_dict)

                                    try:
                                        ip_matches = re.findall(ip_pattern, fd_string)
                                    except:
                                        ip_matches = re.findall(ip_pattern, connection_str)
                                    if ip_matches:
                                        for connection in ip_matches:
                                            network_dict = {'clientIP': ip_matches[0],
                                                            'clientPort': None,
                                                            'serverIP': ip_matches[1],
                                                            'serverPort': None
                                                            }
                                            if network_dict not in process_entry['network_list']:
                                                process_entry['network_list'].append(network_dict)

                        elif not new_process_inst.files_list:
                            file_matches = re.findall(file_path_pattern, fd_string)
                            if file_matches:
                                for file in file_matches:
                                    file_dict = {'path': file,
                                                 'action': syscall.name()}
                                    new_process_inst.files_list.append(file_dict)

                        if not new_process_inst.network_list:
                            ip_matches = re.findall(ip_pattern, fd_string)
                            if ip_matches:
                                for connection in ip_matches:
                                    network_dict = {'clientIP': ip_matches[0],
                                                    'clientPort': None,
                                                    'serverIP': ip_matches[1],
                                                    'serverPort': None
                                                    }
                                    new_process_inst.network_list.append(network_dict)

    pprint.pprint(vars(alert))
    break
