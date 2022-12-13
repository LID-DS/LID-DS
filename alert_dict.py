import re
import json
import pprint
from dataloader.dataloader_factory import dataloader_factory

ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
port_pattern = re.compile(r"(?::)([0-9]+)")  # not bulletproof
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")

def extract_arg(arg_name: str):
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
    def __init__(self, ds_path, time_window, syscall_count):
        self.alert_id = None
        self.path = ds_path
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

        def arg_match_and_append(self, arg_str: str):

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
                        if ip in known_ips:
                            known = True
                        else:
                            known = False

                        network_dict = {'client_ip': ip_matches[0],
                                        'client_port': port_matches[0],
                                        'server_ip': ip_matches[1],
                                        'server_port': port_matches[1],
                                        'dest_ip_known': known
                                        }
                        if not self.network_list:
                            self.network_list.append(network_dict)
                        else:
                            if network_dict not in self.network_list:
                                duplicate = False
                                for entry in self.network_list:
                                    if entry['client_port'] == network_dict['client_port'] and entry['server_ip'] == \
                                            network_dict['server_ip'] and entry['server_port'] == network_dict[
                                            'server_port'] and entry['dest_ip_known'] == network_dict[
                                            'dest_ip_known'] and entry['client_port'] != network_dict['client_port']:
                                        duplicate = True
                                        continue
                                if not duplicate:
                                    self.network_list.append(network_dict)

                if file_matches:
                    for file in file_matches:
                        if file in known_files:
                            known = True
                        else:
                            known = False

                        file_dict = {'path': file,
                                     'action': syscall.name(),
                                     'known': known
                                     }
                        if file_dict not in self.files_list:
                            self.files_list.append(file_dict)

            else:
                return


if __name__ == '__main__':

    # data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
    # alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    # scenario_path = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021/CVE-2017-7529'
    # alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
    #scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'

    alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarme/alarms_som_ngram7_w2v_CVE-2020-23839.json'
    scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2020-23839'


    dataloader = dataloader_factory(scenario_path)
    alert_file = open(alert_file_path)
    alert_dict = json.load(alert_file)

    output = {'alerts': []}

    args_analyzed = ['fd', 'out_fd', 'in_fd']
    known_files = []
    known_ips = []

    # saving files touched in training
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

        # accessing syscall batch from alert
        for recording in dataloader.test_data():
            if recording.name == recording_alert:
                for syscall in recording.syscalls():
                    if syscall.line_id in range(first_line_id, last_line_id + 1):

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
                            current_process.arg_match_and_append(extract_arg(arg))

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
