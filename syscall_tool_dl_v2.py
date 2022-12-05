import re
import json
import pprint
from dataloader.dataloader_factory import dataloader_factory
from dataloader import syscall_2021

ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
port_pattern = re.compile(r"(?::)([0-9]+)")                     #not bulletproof
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")


def extract_arg(arg_name: str):

    """extracts value from systemcall parameter dict given arguments name,
        returns argument string"""

    try:
        arg_str = syscall.params()[arg_name]
    except KeyError:
        # print(f"Argument {arg_name} not in system call.")
        return

    return arg_str


class Alert:
    def __init__(self, ds_path, time_window, syscall_count):
        self.alert_id = None
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

        def arg_match_and_append(self, arg_str: str):

            """takes argument string, matches patterns and appends process information
            if not included already"""

            ip_matches = re.findall(ip_pattern, arg_str)
            port_matches = re.findall(port_pattern, arg_str)
            file_matches = re.findall(file_path_pattern, arg_str)

            if ip_matches and port_matches:
                for ip in ip_matches:
                    network_dict = {'clientIP': ip_matches[0],
                                    'clientPort': port_matches[0],
                                    'serverIP': ip_matches[1],
                                    'serverPort': port_matches[1]
                                    }
                    if network_dict not in self.network_list:
                        self.network_list.apend(network_dict)

            if file_matches:
                for file in file_matches:
                    file_dict = {'path': file,
                                 'action': syscall.name()
                                 }
                    if file_dict not in self.files_list:
                        self.files_list.append(file_dict)


if __name__ == '__main__':
    #loading data
    # data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
    # alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'
    # scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'

    dataloader = dataloader_factory(scenario_path)
    alert_file = open(alert_file_path)
    alert_dict = json.load(alert_file)

    # looping over every entry in input alert file
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

                        # creating new process entry in alarm dict if not existing
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


    ??????????????
                        # extracting argument information from current syscall
                        if 'fd' in syscall.params() or 'out_fd' in syscall.params():
                            try:
                                fd_string = syscall.params()['fd']
                            except KeyError:
                                try:
                                    connection_str = syscall.params()['out_fd']
                                    file_str = syscall.params()['in_fd']
                                    in_out = True
                                except KeyError:
                                    print("No fd to match.")

                            if existing_process:
                                for process_entry in alert.process_list:
                                    if process_entry['process_id'] == syscall.process_id():
                                        try:
                                            file_matches = re.findall(file_path_pattern, fd_string)
                                        except KeyError:
                                            file_matches = re.findall(file_path_pattern, file_str)

                                        if file_matches:
                                            for file in file_matches:
                                                file_dict = {'path': file,
                                                             'action': syscall.name()}
                                                if file_dict not in process_entry['files_list']:
                                                    process_entry['files_list'].append(file_dict)

                                        try:
                                            ip_matches = re.findall(ip_pattern, fd_string)
                                            port_matches = re.findall(port_pattern, fd_string)
                                        except KeyError:
                                            ip_matches = re.findall(ip_pattern, connection_str)
                                            port_matches = re.findall(port_pattern, connection_str)

                                        if ip_matches:
                                            for connection in ip_matches:
                                                network_dict = {'clientIP': ip_matches[0],
                                                                'clientPort': port_matches[0],
                                                                'serverIP': ip_matches[1],
                                                                'serverPort': port_matches[1]
                                                                }
                                                if network_dict not in process_entry['network_list']:
                                                    process_entry['network_list'].append(network_dict)
                            else:
                                if in_out:
                                    file_matches = re.findall(file_str, file_path_pattern)
                                    ip_matches = re.findall(connection_str, ip_pattern)
                                    port_matches = re.findall(connection_str, port_pattern)

                                else:
                                    file_matches = re.findall(file_path_pattern, fd_string)
                                    port_matches = re.findall(port_pattern, fd_string)
                                    ip_matches = re.findall(ip_pattern, fd_string)

                                if file_matches:
                                    for file in file_matches:
                                        file_dict = {'path': file,
                                                     'action': syscall.name()}
                                        new_process_inst.files_list.append(file_dict)

                                if ip_matches and port_matches:
                                    for connection in ip_matches:
                                        network_dict = {'clientIP': ip_matches[0],
                                                        'clientPort': port_matches[0],
                                                        'serverIP': ip_matches[1],
                                                        'serverPort': port_matches[1]
                                                        }
                                        new_process_inst.network_list.append(network_dict)

        pprint.pprint(vars(alert))
        break
