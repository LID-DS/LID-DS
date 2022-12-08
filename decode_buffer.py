from dataloader.direction import Direction
from dataloader.dataloader_factory import dataloader_factory



# lid_ds_base_path = "/home/mly/PycharmProjects/LID-DS-2021/LID-DS-2021"
lid_ds_base_path = "/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021"
lid_ds_version = "LID-DS-2021"

scenario_names = [
    "CVE-2017-7529",
    "CVE-2014-0160",
    "CVE-2012-2122",
    "Bruteforce_CWE-307",
    "CVE-2020-23839",
    "CWE-89-SQL-injection",
    "PHP_CWE-434",
    "ZipSlip",
    "CVE-2018-3760",
    "CVE-2020-9484",
    "EPS_CWE-434",
    "CVE-2019-5418",
    "Juice-Shop",
    "CVE-2020-13942",
    "CVE-2017-12635_6"
]
syscall_names = []

for select_scenario_number in range(0, len(scenario_names)):
    scenario_path = f"{lid_ds_base_path}/{scenario_names[select_scenario_number]}"
    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

    for recording in dataloader.test_data():
        for syscall in recording.syscalls():
            if syscall.process_id() == 1286020:
                print(syscall.syscall_line)

