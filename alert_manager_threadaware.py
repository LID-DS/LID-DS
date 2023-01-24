import re
import json
import copy
import pprint
from datetime import datetime

from tqdm import tqdm

from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
port_pattern = re.compile(r"(?::)([0-9]+)")  # not bulletproof
file_path_pattern = re.compile(r"((\/\w+)+(\.\w+)?)")  # old one


# file_path_pattern = re.compile(r"(?<=<f>)(.*)(?=\))")


def save_basic_info(alarm_entry):
    """
    saves information from alarm entry,
    returns dict
    """
    if alarm_entry['first_line_id'] == alarm_entry['last_line_id']:
        syscall_count = 1
    else:
        syscall_count = alarm_entry['last_line_id'] - alarm_entry['first_line_id']

    if alarm_entry['last_timestamp'] == alarm_entry['first_timestamp']:
        time_window_seconds = 0
    else:
        time_window_seconds = float(
            "{:.3f}".format((alarm_entry['last_timestamp'] - alarm_entry['first_timestamp']) * pow(10, -9)))

    basic_alarm_info = {'scenario_path': alarm_entry['filepath'],
                        'alert_recording': alarm_entry['filepath'].strip("/'").split('/')[3].strip(".zip"),
                        'first_timestamp': alarm_entry['first_timestamp'],
                        'last_timestamp': alarm_entry['last_timestamp'],
                        'time_window_seconds': time_window_seconds,
                        'syscall_count': syscall_count,
                        'first_line_id': alarm_entry['first_line_id'],
                        'last_line_id': alarm_entry['last_line_id']}

    return basic_alarm_info


def learn_files(dataloader):
    """
    saves 'fd' information from arguments in training data,
    returns lists of known_files(0) and known_ips(1)
    """
    known_files = []

    for recording in tqdm(dataloader.training_data(), desc="Learning training data...", unit=" recording"):
        for syscall in recording.syscalls():
            if 'fd' in syscall.params().keys():
                matched_files = re.findall(file_path_pattern, syscall.params()['fd'])
                ip_matches = re.findall(ip_pattern, syscall.params()['fd'])

                if matched_files:
                    for file in matched_files:
                        if file not in known_files:
                            known_files.append(file)

    return known_files


def is_duplicate_connection(dict_to_check: dict, network_list: dict):
    """
    returns true if network dict has same values except different client port
    """

    duplicate = False
    for entry in network_list:
        if entry['source_ip'] != dict_to_check['source_ip']:
            continue
        elif entry['dest_ip'] != dict_to_check['dest_ip']:
            continue
        elif entry['dest_port'] != dict_to_check['dest_port']:
            continue
        elif entry['source_port'] != dict_to_check['source_port']:
            duplicate = True

    return duplicate


def append_file(dict_to_check: dict, files_list: dict):
    """
    returns updated files list for process,
    appends either new file or adds new action to existing one
    """

    duplicate = False
    action = dict_to_check['action'][0]
    for file in files_list:
        if dict_to_check['path'] == file['path']:
            if action not in file['action']:
                file['action'].append(action)
                file['occurrences'] += 1
                duplicate = True
                break
            elif action in file['action']:
                file['occurrences'] += 1
                return files_list

    if not duplicate:
        files_list.append(dict_to_check)

    return files_list


def check_known(attribute, attribute_list: list):
    """
    checks if attribute appeared in training,
    returns bool
    """

    if attribute in attribute_list:
        known = True
    else:
        known = False

    return known


def extract_arg_str(arg_name: str, syscall):
    """
    extracts value from syscall parameter dict given arguments name,
    returns argument string
    """

    try:
        arg_str = syscall.params()[arg_name]
    except KeyError:
        # print(f"Argument {arg_name} not in system call.")
        return None

    return arg_str


def filter_known(list_of_attributes: list):
    """
    returns new list that only includes items not known form training
    """
    try:
        filtered_list = [item for item in list_of_attributes if item['known'] is False]
        return filtered_list
    except KeyError:
        print("List entries do not have 'known' attribute.")


def set_process(syscall, current_alert):
    """
    set current process or create new process entry in process list of current alert
    """

    if current_alert.process_list:
        if not any(process.process_id == syscall.process_id() for process in current_alert.process_list):
            current_process = current_alert.Process(syscall.process_id(), syscall.user_id(),
                                                    syscall.process_name())
            current_alert.process_list.append(current_process)

        else:
            for process in current_alert.process_list:
                if process.process_id == syscall.process_id():
                    current_process = process

    else:
        current_process = current_alert.Process(syscall.process_id(), syscall.user_id(),
                                                syscall.process_name())
        current_alert.process_list.append(current_process)

    return current_process


def shorten(alert_dict: dict):
    """
    removes all information irrelevant for analysis from dict
    """

    keys_to_hide = ['path_to_syscalls', 'recording_name', 'first_line_id',
                    'last_line_id']
    alert_dict_shortened = alert_dict.copy()
    for key in keys_to_hide:
        alert_dict_shortened.pop(key)

    return alert_dict_shortened


def save_to_file(alert_dict: dict):
    with open('alerts.json', 'a') as alert_output_file:
        json.dump(alert_dict, alert_output_file, indent=2)
        print("--> Output saved to json.")


def construct_file_dict(tuple, syscall, known_files):
    file_path = tuple[1]

    file_dict = {'path': file_path,
                 'action': [syscall.name()],
                 'known': check_known(file_path, known_files),
                 'occurrences': 1
                 }

    return file_dict


def stringmatch_arg(arg_tuple, syscall, known_files):
    fd_string = arg_tuple[1]
    ip_matches = re.findall(ip_pattern, fd_string)
    port_matches = re.findall(port_pattern, fd_string)
    file_matches = re.findall(file_path_pattern, fd_string)

    if file_matches:
        file_path = file_matches[0][0]

        file_dict = {'path': file_path,
                     'action': [syscall.name()],
                     'known': check_known(file_path, known_files),
                     'occurrences': 1
                     }
        return file_dict

    if ip_matches and port_matches and len(ip_matches) > 1:  # so 0.0.0.0 won't be listed

        network_dict = {'source_ip': ip_matches[0],
                        'source_port': port_matches[0],
                        'dest_ip': ip_matches[1],
                        'dest_port': port_matches[1],
                        }
        return network_dict


class Alert:
    def __init__(self, basic_info):
        self.alert_id = None
        self.path_to_syscalls = basic_info['scenario_path']
        self.recording_name = basic_info['alert_recording']
        self.first_line_id = basic_info['first_line_id']
        self.last_line_id = basic_info['last_line_id']
        self.first_timestamp = basic_info['first_timestamp']
        self.last_timestamp = basic_info['last_timestamp']
        self.time_window = basic_info['time_window_seconds']
        self.syscall_count = basic_info['syscall_count']
        self.process_list = []

    def set_id(self):
        pass

    def dictify_processes(self):
        processes_as_dicts = []
        for entry in self.process_list:
            entry_dict = vars(entry)
            processes_as_dicts.append(entry_dict)
        self.process_list = processes_as_dicts

        return self.process_list

    def convert_timestamp(self):
        """
        converts timestamps in ns to date time format
        """
        self.first_timestamp = (datetime.fromtimestamp(self.first_timestamp // 1000000000)).strftime(
            '%Y-%m-%d %H:%M:%S')
        self.last_timestamp = (datetime.fromtimestamp(self.last_timestamp // 1000000000)).strftime('%Y-%m-%d %H:%M:%S')

    def show(self, show_known: bool):
        """
        print alert object as dict, show_known flag for view that excludes known files
        """
        if show_known:
            pprint.pprint(vars(self))
            return vars(self)

        else:
            filter_dict = vars(self)
            for process in filter_dict['process_list']:
                process['files_list'] = filter_known(process['files_list'])
            pprint.pprint(filter_dict)
            return filter_dict

    class Process:
        def __init__(self, process_id, user_id, process_name):
            self.process_id = process_id
            self.user_id = user_id
            self.process_name = process_name
            self.network_list = []
            self.files_list = []
            self.parent_thread = None

        def analyze_arguments(self, syscall, analyzed_args: list, known_files):

            args_found = [arg for arg in analyzed_args if arg in syscall.params().keys()]

            if len(args_found) == 1:
                arg_tuple = (args_found[0], syscall.param(args_found[0]))
                if any(arg_tuple[0] == arg for arg in ["name", "filename", "path", "in_fd"]):
                    fd_dict = construct_file_dict(arg_tuple, syscall, known_files)
                    self.files_list = append_file(fd_dict, self.files_list)

                if arg_tuple[0] == "fd":
                    fd_dict = stringmatch_arg(arg_tuple, syscall, known_files)

                    if fd_dict is not None:
                        if "dest_ip" in fd_dict.keys():
                            if not self.network_list:
                                self.network_list.append(fd_dict)
                            else:
                                if fd_dict not in self.network_list:
                                    if not is_duplicate_connection(fd_dict, self.network_list):
                                        self.network_list.append(fd_dict)

                        else:
                            self.files_list = append_file(fd_dict, self.files_list)

            if len(args_found) == 2:
                arg_tuple = (args_found[1], syscall.param(args_found[1]))
                if arg_tuple[0] == "name":
                    fd_dict = construct_file_dict(arg_tuple, syscall, known_files)
                    self.files_list = append_file(fd_dict, self.files_list)

        def trace_parent(self, syscall):
            """
            checks for occurrence of clone and execve syscalls in order to extract parent thread information,
            returns ptid
            """

            if syscall.name() == 'clone':
                try:
                    ptid = syscall.param('ptid')
                    self.parent_thread = (ptid, syscall.name())
                    return ptid
                except:
                    pass

            if syscall.name() == 'execve':
                try:
                    ptid = syscall.param('ptid')
                    self.parent_thread = (ptid, syscall.name())
                    return ptid
                except:
                    pass

        def check_sendfile(self, syscall):
            """
            extract connection and file information from sendfile syscall
            """
            if syscall.name() == "sendfile":
                if syscall.direction() == Direction.OPEN:
                    connection_info = syscall.param("out_fd")
                    fd = syscall.param("in_fd")


def is_consecutive(previous_alert, current_alert):
    """
    returns True if current alert happens within defined timespan after previous, else False
    """

    timespan_ns = 10 * pow(10, 9)  # 10 seconds timespan

    if (current_alert.first_timestamp - previous_alert.last_timestamp) < timespan_ns:
        return True
    else:
        return False


def update_last_alert(last_timestamp, last_line_id, current_alert):
    """
    updates last processed alert with information from consecutive alert: groups them
    """
    intermediate_line_id = current_alert.last_line_id
    current_alert.last_timestamp = last_timestamp
    current_alert.last_line_id = last_line_id
    current_alert.time_window = float("{:.3f}".format((last_timestamp - current_alert.first_timestamp) * pow(10, -9)))
    current_alert.syscall_count = last_line_id - current_alert.first_line_id

    return current_alert, intermediate_line_id


if __name__ == '__main__':

    # alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    # scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'
    # anomaly_file_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/Alarme_Alerts/alarme/alarms_som_ngram7_w2v_Bruteforce_CWE-307.json'
    anomaly_file_path = "alarms_SOM_EPS_ngram_7_epoch_100_w2v_5_CWE-434.json"
    scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/EPS_CWE-434'

    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

    output = {'alerts': []}  # dict for json output
    alert_list = []  # list for saving alert objects

    analyzed_args = ['fd', 'path', 'name', 'filename']

    known_files = learn_files(dataloader)

    with open(anomaly_file_path) as anomaly_file:
        anomaly_dict = json.load(anomaly_file)

        # looping over every entry in input alert file
        for entry in anomaly_dict['alarms']:
            anomaly_info = save_basic_info(entry)

            alert = Alert(anomaly_info)

            alert_list.append(alert)

    for recording in tqdm(dataloader.test_data(), desc="Iterating recordings...", unit=" recording"):

        alerts_of_recording = [alert for alert in alert_list if alert.recording_name == recording.name]
        alerts_grouped = []
        first_alert_of_recording = True
        updated_alert = False

        for alert in alerts_of_recording:
            new_alert = True
            current_alert = alert
            if not first_alert_of_recording:
                if is_consecutive(alerts_grouped[-1], current_alert):
                    last_timestamp = current_alert.last_timestamp
                    last_line_id = current_alert.last_line_id
                    current_alert = alerts_grouped[-1]
                    current_alert, intermediate_line_id = update_last_alert(last_timestamp, last_line_id, current_alert)
                    updated_alert = True

            for syscall in recording.syscalls():

                if current_alert.syscall_count == 1:
                    if current_alert.first_line_id == syscall.line_id:
                        current_process = set_process(syscall, current_alert)

                        current_process.analyze_arguments(syscall, analyzed_args, known_files)
                        current_process.trace_parent(syscall)
                        current_process.check_sendfile(syscall)
                else:
                    if updated_alert:  # for updated alerts only new system call lines analyzed
                        if syscall.line_id in range(intermediate_line_id, current_alert.last_line_id + 1):
                            if new_alert:
                                first_syscall_of_alert = True
                                new_alert = False
                            else:
                                first_syscall_of_alert = False

                            if first_syscall_of_alert:
                                first_thread = syscall.thread_id()
                            elif not first_syscall_of_alert:
                                if not syscall.thread_id() == first_thread:
                                    break

                            current_process = set_process(syscall, current_alert)

                            current_process.analyze_arguments(syscall, analyzed_args, known_files)
                            current_process.trace_parent(syscall)
                            current_process.check_sendfile(syscall)
                    else:
                        if syscall.line_id in range(current_alert.first_line_id, current_alert.last_line_id + 1):
                            if new_alert:
                                first_syscall_of_alert = True
                                new_alert = False
                            else:
                                first_syscall_of_alert = False

                            if first_syscall_of_alert:
                                first_thread = syscall.thread_id()
                            elif not first_syscall_of_alert:
                                if not syscall.thread_id() == first_thread:
                                    break

                            current_process = set_process(syscall, current_alert)

                            current_process.analyze_arguments(syscall, analyzed_args, known_files)
                            current_process.trace_parent(syscall)
                            current_process.check_sendfile(syscall)

            if not updated_alert:
                alerts_grouped.append(copy.deepcopy(current_alert))
                first_alert_of_recording = False
                updated_alert = False

        for alert in alerts_grouped:
            alert.dictify_processes()
            alert.convert_timestamp()
            single_alert = alert.show(show_known=True)  # pprint alert as dict
            single_alert_shortened = shorten(single_alert)  # hide path and recording information for analysis
            output['alerts'].append(single_alert)

        if alerts_grouped:
            break

    #save_to_file(output)
