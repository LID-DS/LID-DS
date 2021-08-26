import glob
import json
import os
import sys
from enum import Enum


class RunType(Enum):
    NORMAL = 1
    NORMAL_AND_ATTACK = 2
    ONLY_ATTACK = 3
    NOTHING = 4


class SubFolder(Enum):
    TRAINING = "training"
    VALIDATION = "validation"
    TEST = "test"
    TEST_NORMAL = "test/normal"
    TEST_NORMAL_AND_ATTACK = "test/normal_and_attack"


class Modes(Enum):
    TRAINING = 1
    VALIDATION = 2
    TEST = 3


def remove_file(file_to_remove: str):
    if os.path.isfile(file_to_remove):
        print(f"File {file_to_remove} exist: delete it!")
        os.remove(file_to_remove)
    else:
        print(f"File {file_to_remove} does not exist.")


def create_subfolder(folder_to_create: str):
    if os.path.isdir(folder_to_create):
        print(f"Folder {folder_to_create} already exist.")
    else:
        print(f"Folder {folder_to_create} does not exist, create it.")
        os.mkdir(folder_to_create)


def get_type_of_run(json_file_name: str) -> RunType:
    # run_name = json_file_name[:-5]
    # run_name = run_name[run_name.rfind("/")+1:]
    with open(json_file_name) as f:
        data = json.load(f)

        normal_behavoiur = False
        exploit = False

        # check for normal behaviour:
        for container in data["container"]:
            if container["role"] == "normal":
                normal_behavoiur = True
                break
        # check for exploit
        if data["exploit"]:
            exploit = True

        if normal_behavoiur is False and exploit is False:
            return RunType.NOTHING
        if normal_behavoiur is False and exploit is True:
            return RunType.ONLY_ATTACK
        if normal_behavoiur is True and exploit is False:
            return RunType.NORMAL
        if normal_behavoiur is True and exploit is True:
            return RunType.NORMAL_AND_ATTACK


def convert_scap_to_sc(json_file):
    # build the filename of the scap file
    json_base_name = os.path.basename(json_file)
    dir_name = os.path.dirname(json_file)
    run_name = os.path.splitext(json_base_name)[0]
    scap_name = os.path.join(dir_name, run_name) + ".scap"
    sc_name = os.path.join(dir_name, run_name) + ".sc"
    os.system(f'sysdig -v -b -p "%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %syscall.type %evt.dir %evt.args" -r {scap_name} "proc.pid != -1" > {sc_name}')
    # sysdig -v -x -p "%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %syscall.type %evt.dir %evt.args" -r tangy_franklin_6387.scap "proc.pid != -1"


class Exporter:
    def __init__(self):
        self._last_nothing_got_into = SubFolder.TEST_NORMAL

    def move_files(self, json_file, run_type, counts_dict):
        convert_scap_to_sc(file)
        json_base_name = os.path.basename(json_file)
        dir_name = os.path.dirname(json_file)
        run_name = os.path.splitext(json_base_name)[0]

        sc_base_name = run_name + ".sc"
        pcap_base_name = run_name + ".pcap"
        res_base_name = run_name + ".res"

        print(f"current run: {run_name} -> {run_type} ", end="", flush=True)

        if run_type == RunType.NORMAL:
            if counts_dict[Modes.TRAINING] > 0:
                counts_dict[Modes.TRAINING] -= 1
                print(f"-> {SubFolder.TRAINING.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, res_base_name))
            elif counts_dict[Modes.VALIDATION] > 0:
                counts_dict[Modes.VALIDATION] -= 1
                print(f"-> {SubFolder.VALIDATION.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, res_base_name))
            else:
                print(f"-> {SubFolder.TEST_NORMAL.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, res_base_name))

        elif run_type == RunType.NORMAL_AND_ATTACK or run_type == RunType.ONLY_ATTACK:
            print(f"-> {SubFolder.TEST_NORMAL_AND_ATTACK.value}")
            os.rename(os.path.join(dir_name, json_base_name),
                      os.path.join(dir_name, SubFolder.TEST_NORMAL_AND_ATTACK.value, json_base_name))
            os.rename(os.path.join(dir_name, sc_base_name),
                      os.path.join(dir_name, SubFolder.TEST_NORMAL_AND_ATTACK.value, sc_base_name))
            os.rename(os.path.join(dir_name, pcap_base_name),
                      os.path.join(dir_name, SubFolder.TEST_NORMAL_AND_ATTACK.value, pcap_base_name))
            os.rename(os.path.join(dir_name, res_base_name),
                      os.path.join(dir_name, SubFolder.TEST_NORMAL_AND_ATTACK.value, res_base_name))
        elif run_type == RunType.NOTHING:
            # one after another into TRAINING, VALIDATION and TEST_NORMAL
            if self._last_nothing_got_into == SubFolder.TEST_NORMAL:
                self._last_nothing_got_into = SubFolder.TRAINING
                print(f"-> {SubFolder.TRAINING.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.TRAINING.value, res_base_name))
            elif self._last_nothing_got_into == SubFolder.TRAINING:
                self._last_nothing_got_into = SubFolder.VALIDATION
                print(f"-> {SubFolder.VALIDATION.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.VALIDATION.value, res_base_name))
            elif self._last_nothing_got_into == SubFolder.VALIDATION:
                self._last_nothing_got_into = SubFolder.TEST_NORMAL
                print(f"-> {SubFolder.TEST_NORMAL.value}")
                os.rename(os.path.join(dir_name, json_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, json_base_name))
                os.rename(os.path.join(dir_name, sc_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, sc_base_name))
                os.rename(os.path.join(dir_name, pcap_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, pcap_base_name))
                os.rename(os.path.join(dir_name, res_base_name),
                          os.path.join(dir_name, SubFolder.TEST_NORMAL.value, res_base_name))


if __name__ == '__main__':
    counts = {
        Modes.TRAINING: 2,
        Modes.VALIDATION: 2
    }

    scenario = sys.argv[1]
    scenario_path = os.path.join(scenario, "runs")
    print(f"working on: {scenario_path}")

    # delete runs.log
    remove_file(os.path.join(scenario_path, "runs.log"))

    # create subfolders
    create_subfolder(os.path.join(scenario_path, SubFolder.TRAINING.value))
    create_subfolder(os.path.join(scenario_path, SubFolder.VALIDATION.value))
    create_subfolder(os.path.join(scenario_path, SubFolder.TEST.value))
    create_subfolder(os.path.join(scenario_path, SubFolder.TEST_NORMAL.value))
    create_subfolder(os.path.join(scenario_path, SubFolder.TEST_NORMAL_AND_ATTACK.value))

    # get all json files
    list_of_jsons = [f for f in glob.glob(scenario_path + "/*.json")]

    exp = Exporter()

    # iterate over all json files, parse them and move the corresponding files to sub folders
    counter = 0
    amount = len(list_of_jsons)
    for file in list_of_jsons:
        exp.move_files(file, get_type_of_run(file), counts)
        counter+= 1
        print(f" -- at {counter / amount * 100.0}% --")
