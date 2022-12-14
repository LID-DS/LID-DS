import re
import json
import pprint
from dataloader.dataloader_factory import dataloader_factory

ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
port_pattern = re.compile(r"(?::)([0-9]+)")  # not bulletproof
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")

def save_basic_info(alarm_entry):
    """
    saves information from alarm entry,
    returns dict
    """

    basic_alarm_info = {'scenario_path': alarm_entry['filepath'],
                        'alert_recording': alarm_entry['filepath'].strip("/'").split('/')[3].strip(".zip"),
                        'time_window_seconds': (alarm_entry['last_timestamp'] - alarm_entry['first_timestamp']) * pow(10, -9),
                        'syscall_count': alarm_entry['last_line_id']-alarm_entry['first_line_id'],
                        'first_line_id': alarm_entry['first_line_id'],
                        'last_line_id': alarm_entry['last_line_id']}

    return basic_alarm_info

def learn_training_fds(dataloader):
    """
    saves 'fd' information from argruments in training data,
    returns lists of known_files(0) and known_ips(1)
    """
    known_files = []
    known_ips = []

    for recording in dataloader.training_data():
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
        if entry['client_ip'] != dict_to_check['client_ip']:
            continue
        elif entry['server_ip'] != dict_to_check['server_ip']:
            continue
        elif entry['server_port'] != dict_to_check['server_port']:
            continue
        elif entry['dest_ip_known'] != dict_to_check['dest_ip_known']:
            continue
        elif entry['client_port'] != dict_to_check['client_port']:
            duplicate = True

    return duplicate


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
    extracts value from systemcall parameter dict given arguments name,
    returns argument string
    """

    try:
        arg_str = syscall.params()[arg_name]
    except KeyError:
        #print(f"Argument {arg_name} not in system call.")
        return None

    return arg_str


def filter_known(list: list):
    """
    returns new list that only includes items not known form training
    """
    try:
        filtered_list = [item for item in list if item['known'] is False]
        return filtered_list
    except KeyError:
        try:
            filtered_list = [item for item in list if item['dest_ip_known'] is False]
            return filtered_list
        except KeyError:
            print("List entries do not have 'known' attribute.")


def save_to_file(alert_dict: dict):
    with open('alerts.json', 'a' ) as alert_output_file:
        json.dump(alert_dict, alert_output_file, indent=2)
        print("--> Output saved to json.")


class Alert:
    def __init__(self, path_to_syscalls, recording_name, time_window, syscall_count):
        self.alert_id = None
        self.path_to_syscalls = path_to_syscalls
        self.recording_name = recording_name
        self.time_window = time_window
        self.syscall_count = syscall_count
        self.process_list = []

    def dictify_processes(self):
        for entry in self.process_list:
            entry_dict = vars(entry)
            self.process_list.remove(entry)
            self.process_list.append(entry_dict)

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

        def arg_match_and_append(self, arg_str: str, known_ips, known_files):

            """
            takes argument string, matches patterns and appends process information
            if not included already
            """

            if arg_str is not None:
                ip_matches = re.findall(ip_pattern, arg_str)
                port_matches = re.findall(port_pattern, arg_str)
                file_matches = re.findall(file_path_pattern, arg_str)

                if ip_matches and port_matches:
                    for ip in ip_matches:

                        network_dict = {'client_ip': ip_matches[0],
                                        'client_port': port_matches[0],
                                        'server_ip': ip_matches[1],
                                        'server_port': port_matches[1],
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
                                     'action': syscall.name(),
                                     'known': check_known(file, known_files)
                                     }
                        if file_dict not in self.files_list:
                            self.files_list.append(file_dict)

            else:
                return


if __name__ == '__main__':

    # alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    # scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'
    # alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    # scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'

    alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarme/alarms_som_ngram7_w2v_CVE-2020-23839.json'
    scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2020-23839'


    dataloader = dataloader_factory(scenario_path)
    alert_file = open(alert_file_path)
    alert_dict = json.load(alert_file)

    output = {'alerts': []}

    args_analyzed = ['fd', 'out_fd', 'in_fd']

    known_files, known_ips = learn_training_fds(dataloader)

    # looping over every entry in input alert file
    for entry in alert_dict['alarms']:

        alarm_info = save_basic_info(entry)

        alert = Alert(alarm_info['scenario_path'],
                      alarm_info['alert_recording'],
                      alarm_info['time_window_seconds'],
                      alarm_info['syscall_count'])

        # accessing syscall batch from alert
        for recording in dataloader.test_data():
            if recording.name == alarm_info['alert_recording']:
                for syscall in recording.syscalls():
                    if syscall.line_id in range(alarm_info['first_line_id'], alarm_info['last_line_id'] + 1):

                        # creating new process entry in alarm dict if not existing
                        if alert.process_list:
                            if not any(process.process_id == syscall.process_id() for process in alert.process_list):
                                current_process = alert.Process(syscall.process_id(), syscall.user_id(),
                                                                syscall.process_name())
                            else:
                                for process in alert.process_list:
                                    if process.process_id == syscall.process_id():
                                        current_process = process

                        else:
                            current_process = alert.Process(syscall.process_id(), syscall.user_id(),
                                                            syscall.process_name())
                            alert.process_list.append(current_process)

                        # extracting argument information from current syscall
                        for arg in args_analyzed:
                            current_process.arg_match_and_append(extract_arg_str(arg, syscall), known_ips, known_files)

                        if syscall.name() == 'clone':
                            try:
                                current_process.parent_thread = (syscall.param('ptid'), syscall.name())
                            except:
                                pass

                        if syscall.name() == 'execve':
                            try:
                                current_process.parent_thread = (syscall.param('ptid'), syscall.name())
                            except:
                                pass


        alert.dictify_processes()
        single_alert = alert.show(show_known=True)
        output['alerts'].append(single_alert)

    save_to_file(output)
