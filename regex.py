import re
from dataloader.dataloader_factory import dataloader_factory

scenario_path = '/mnt/0e52d7cb-afd4-4b49-8238-e47b9089ec68/LID-DS-2021/CVE-2017-7529'
dataloader = dataloader_factory(scenario_path)

pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
file_path_pattern = re.compile(r"(\/.*?\.[\w:]+)")
test_pattern = re.compile(r"(?:xdlkjasd)")

"""string = "19(<4t>192.168.240.2:49362->192.168.240.6:80)"
matches = pattern.findall(string)
print(matches)"""

for recording in dataloader.test_data():
    for syscall in recording.syscalls():
        if 'out_fd' in syscall.params().keys():
            string = syscall.params()['out_fd']
            matches = re.findall(test_pattern, string)
            print(matches)

