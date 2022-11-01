import json
from dataloader.dataloader_factory import dataloader_factory

#data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
#alert_file_path = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
alert_file_path = '/home/emmely/PycharmProjects/LIDS/Git LIDS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'
scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'

dataloader = dataloader_factory(scenario_path)

alert_file = open(alert_file_path)
alert_dict = json.load(alert_file)

#iterating through alert entries in input alert file
for entry in alert_dict['alarms']:
    first_line_id = entry['first_line_id']
    last_line_id = entry['last_line_id']
    scenario_path = entry['filepath']
    recording_alert = scenario_path.strip("/'").split('/')[3].strip(".zip")

    for rec in dataloader.test_data():
        if rec.name == recording_alert:
            for syscall in rec.syscalls():
                print(syscall.name())




