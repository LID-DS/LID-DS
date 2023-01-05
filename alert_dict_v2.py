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
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")


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
        time_window_seconds = (alarm_entry['last_timestamp'] - alarm_entry['first_timestamp']) * pow(10, -9)

    starting_time = (datetime.fromtimestamp(alarm_entry['first_timestamp'] // 1000000000)).strftime('%Y-%m-%d %H:%M:%S')

    basic_alarm_info = {'scenario_path': alarm_entry['filepath'],
                        'alert_recording': alarm_entry['filepath'].strip("/'").split('/')[3].strip(".zip"),
                        'first_timestamp': alarm_entry['first_timestamp'],
                        'last_timestamp': alarm_entry['last_timestamp'],
                        'starting_time' : starting_time,
                        'time_window_seconds': time_window_seconds,
                        'syscall_count': syscall_count,
                        'first_line_id': alarm_entry['first_line_id'],
                        'last_line_id': alarm_entry['last_line_id']}

    return basic_alarm_info


def learn_training_fds(dataloader):
    """
    saves 'fd' information from arguments in training data,
    returns lists of known_files(0) and known_ips(1)
    """
    known_files = []
    known_ips = []

    for recording in tqdm(dataloader.training_data(),desc="Learning training data...", unit=" recording" ):
        for syscall in recording.syscalls():
            if 'fd' in syscall.params().keys():
                matched_files = re.findall(file_path_pattern, syscall.params()['fd'])
                ip_matches = re.findall(ip_pattern, syscall.params()['fd'])

                if matched_files:
                    for file in matched_files:
                        if file not in known_files:
                            known_files.append(file)

                if ip_matches:
                    for ip in ip_matches:
                        if ip not in known_ips:
                            known_ips.append(ip)

    return known_files, known_ips


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
        elif entry['dest_ip_known'] != dict_to_check['dest_ip_known']:
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
                duplicate = True
                break
            elif action in file['action']:
                return files_list

    if not duplicate:
        files_list.append(dict_to_check)

    return files_list


def trace_parent(syscall, process):
    """
    checks for occurrence of clone and execve syscalls in order to extract parent thread information,
    returns ptid
    """

    if syscall.name() == 'clone':
        try:
            ptid = syscall.param('ptid')
            process.parent_thread = (ptid, syscall.name())
            return ptid
        except:
            pass

    if syscall.name() == 'execve':
        try:
            ptid = syscall.param('ptid')
            process.parent_thread = (ptid, syscall.name())
            return ptid
        except:
            pass


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
        try:
            filtered_list = [item for item in list_of_attributes if item['dest_ip_known'] is False]
            return filtered_list
        except KeyError:
            print("List entries do not have 'known' attribute.")


def  set_process(syscall, current_alert):
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


def hide_irrelevant(alert_dict: dict):
    """
    removes all information irrelevant for analysis from dict
    """

    keys_to_hide = ['path_to_syscalls', 'recording_name', 'first_timestamp', 'last_timestamp', 'first_line_id', 'last_line_id']
    alert_dict_shortened = alert_dict.copy()
    for key in keys_to_hide:
        alert_dict_shortened.pop(key)

    return alert_dict_shortened


def save_to_file(alert_dict: dict):
    with open('alerts.json', 'a') as alert_output_file:
        json.dump(alert_dict, alert_output_file, indent=2)
        print("--> Output saved to json.")


class Alert:
    def __init__(self, basic_info):
        self.alert_id = None
        self.path_to_syscalls = basic_info['scenario_path']
        self.recording_name = basic_info['alert_recording']
        self.first_line_id = basic_info['first_line_id']
        self.last_line_id = basic_info['last_line_id']
        self.first_timestamp = basic_info['first_timestamp']
        self.last_timestamp = basic_info['last_timestamp']
        self.starting_time = basic_info['starting_time']
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

    def show(self, show_known: bool):
        """
        print alert as dict, show_known flag for view that excludes known files and destination ips
        """
        if show_known:
            pprint.pprint(vars(self))
            return vars(self)

        else:
            filter_dict = vars(self)
            for process in filter_dict['process_list']:
                process['files_list'] = filter_known(process['files_list'])
                process['network_list'] = filter_known(process['network_list'])
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

        def arg_match(self, arg_str: str, known_ips, known_files):

            """
            takes argument string, matches patterns and appends process information
            if not included already
            """

            if arg_str is not None:
                ip_matches = re.findall(ip_pattern, arg_str)
                port_matches = re.findall(port_pattern, arg_str)
                file_matches = re.findall(file_path_pattern, arg_str)

                if ip_matches and port_matches and len(ip_matches) > 1:  # so 0.0.0.0 won't be listed
                    for ip in ip_matches:

                        network_dict = {'source_ip': ip_matches[0],
                                        'source_port': port_matches[0],
                                        'dest_ip': ip_matches[1],
                                        'dest_port': port_matches[1],
                                        'dest_ip_known': check_known(ip, known_ips)
                                        }
                        if not self.network_list:
                            self.network_list.append(network_dict)
                        else:
                            if network_dict not in self.network_list:
                                if not is_duplicate_connection(network_dict, self.network_list):
                                    self.network_list.append(network_dict)

                if file_matches:
                    for file in file_matches:
                        file_dict = {'path': file,
                                     'action': [syscall.name()],
                                     'known': check_known(file, known_files)
                                     }

                        self.files_list = append_file(file_dict, self.files_list)

            else:
                return


def is_consecutive(previous_alert, current_alert):
    """
    returns True if current alert happens within defined timespan after previous, else False
    """

    timespan_ns = 10 * pow(10, 9) # 10 seconds timespan

    if (current_alert.first_timestamp - previous_alert.last_timestamp) < timespan_ns:
        return True
    else:
        return False

def update_log(last_timestamp, last_line_id, current_alert):
    current_alert.last_timestamp = last_timestamp
    current_alert.last_line_id = last_line_id
    current_alert.time_window = (last_timestamp - current_alert.first_timestamp) * pow(10, -9)
    current_alert.syscall_count = last_line_id - current_alert.first_line_id


if __name__ == '__main__':

    # alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    # scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'
    anomaly_file_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/Alarme_Alerts/alarme/alarms_som_ngram7_w2v_CVE-2020-23839.json'
    scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2020-23839'

    # alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarme/alarms_som_ngram7_w2v_CVE-2020-23839.json'
    # scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2020-23839'
    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

    output = {'alerts': []}  # dict for json output
    alert_list = []  # list for saving alert objects

    analyzed_args = ['fd', 'out_fd', 'in_fd', 'res', 'path']

    known_files, known_ips = learn_training_fds(dataloader)

    with open(anomaly_file_path) as anomaly_file:
        anomaly_dict = json.load(anomaly_file)

        # looping over every entry in input alert file
        for entry in anomaly_dict['alarms']:
            anomaly_info = save_basic_info(entry)

            alert = Alert(anomaly_info)

            alert_list.append(alert)

    for recording in dataloader.test_data():

        alerts_of_recording = [alert for alert in alert_list if alert.recording_name == recording.name]
        logs_from_alerts = []
        first = True
        updated_log = False

        for alert in alerts_of_recording:
            current_alert = alert
            if not first:
                if is_consecutive(logs_from_alerts[-1], current_alert):
                    last_timestamp = current_alert.last_timestamp
                    last_line_id = current_alert.last_line_id
                    current_alert = logs_from_alerts[-1]
                    update_log(last_timestamp, last_line_id, current_alert)
                    updated_log = True

            for syscall in recording.syscalls():
                if current_alert.syscall_count == 1:
                    if current_alert.first_line_id == syscall.line_id:
                        current_process = set_process(syscall, current_alert)

                        # extracting argument information from current syscall and adding them to process
                        for arg in analyzed_args:
                            current_process.arg_match(extract_arg_str(arg, syscall), known_ips, known_files)

                        trace_parent(syscall, current_process)  # saving ptid for clone and execve syscalls

                elif syscall.line_id in range(current_alert.first_line_id, current_alert.last_line_id + 1):
                    current_process = set_process(syscall, current_alert)

                    # extracting argument information from current syscall and adding them to process
                    for arg in analyzed_args:
                        current_process.arg_match(extract_arg_str(arg, syscall), known_ips, known_files)

                    trace_parent(syscall, current_process)  # saving ptid for clone and execve syscalls

            if not updated_log:
                logs_from_alerts.append(copy.deepcopy(current_alert))
            first = False
            updated_log = False

        for log in logs_from_alerts:
            log.dictify_processes()
            single_alert = log.show(show_known=True)  # pprint alert as dict
            single_alert_shortened = hide_irrelevant(single_alert)  # hide path and recording information for analysis
            output['alerts'].append(single_alert)

        if logs_from_alerts:
            break

    save_to_file(output)
