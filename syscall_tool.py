from dataloader.dataloader_factory import dataloader_factory

data_base = '/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021'
alert_file = '/home/mly/PycharmProjects/LID-DS/alarms_n_3_w_100_t_False_LID-DS-2021_CVE-2017-7529.json'

dataloader = dataloader_factory(data_base)

for recording in dataloader.test_data():
    for syscall in recording.syscalls():
        print(syscall.name)