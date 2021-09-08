import os
import os.path
import sys
import time
from datetime import datetime
from lid_ds.export.export import RunType, get_type_of_run
import collections

rows = 0
columns = 0


def check_for_missing_files(path: str, file: str, missing: set):
    # get file ending of file name
    ending = file.split(".")[-1]
    # get prefix of file name
    prefix = file[:-len(ending)]
    for file_type in ["scap", "pcap", "res", "json"]:
        # search for type
        if ending != file_type:
            if not os.path.isfile(path + prefix + file_type):
                missing.add(prefix + file_type)


def check_file_sizes(path: str, file: str, small: set):
    size = os.path.getsize(path + file)
    if size == 0:
        small.add(file)


def check_each_file(path: str):
    files_in_scenario = os.listdir(path)
    files_in_scenario.sort()
    missing_files = set()
    small_files = set()
    type_of_runs = collections.Counter()
    for f in files_in_scenario:
        if f == "runs.log":
            continue
        check_for_missing_files(path, f, missing_files)
        check_file_sizes(path, f, small_files)
        if f.endswith(".json"):
            tor = get_type_of_run(path + f)
            type_of_runs[tor.name] += 1

    if len(type_of_runs) > 0:
        print(f" [{type_of_runs[RunType.NORMAL.name]}, {type_of_runs[RunType.NORMAL_AND_ATTACK.name]}, {type_of_runs[RunType.ONLY_ATTACK.name]}, {type_of_runs[RunType.IDLE.name]}]")

    if len(missing_files) > 0:
        print("missing files:".rjust(25) + " ", end='')
        for mf in missing_files:
            print(mf + ", ", end='')
        print()

    if len(small_files) > 0:
        print("small files:".rjust(25) + " ", end='')
        for sf in small_files:
            print(sf + ", ", end='')
        print()


def check_scenario(base: str, scenario: str):
    path = os.path.join(base, scenario + "runs/")
    if os.path.exists(path):
        num_files = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
        expected_number = 1000 + 100 + 20 + 30        
        done = num_files / 4 / expected_number * 100.0
        print(scenario[:-1].rjust(24) + ": ", end='')
        print(f"{done:.2f}%".rjust(7), end='')
        check_each_file(path)
        line = "-" * columns
        print(line)


if __name__ == '__main__':
    path = os.getcwd()
    while True:
        columns = int(os.popen('stty size', 'r').read().split()[1])
        os.system('clear')
        now = datetime.now()        
        print(f"--- Time: {now.strftime('%H:%M:%S')} ---")
        check_scenario(path, "Bruteforce_CWE-307/")
        check_scenario(path, "CVE-2012-2122/")
        check_scenario(path, "CVE-2014-0160/")
        check_scenario(path, "CVE-2017-12635_6/")
        check_scenario(path, "CVE-2017-7529/")
        check_scenario(path, "CVE-2018-3760/")
        check_scenario(path, "CVE-2019-5418/")
        check_scenario(path, "CVE-2020-13942/")
        check_scenario(path, "CVE-2020-23839/")
        check_scenario(path, "CVE-2020-9484/")
        check_scenario(path, "CWE-89-SQL-injection/")
        check_scenario(path, "EPS_CWE-434/")
        check_scenario(path, "Juice-Shop/")
        check_scenario(path, "PHP_CWE-434/")
        check_scenario(path, "ZipSlip/")
        time.sleep(10)
