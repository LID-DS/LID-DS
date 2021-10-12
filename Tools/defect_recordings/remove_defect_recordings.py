import os.path
import json

list_of_defect_files = ["CVE-2017-12635_6/test/normal/scruffy_mendel_1513.zip",
                        "CVE-2017-12635_6/test/normal/skinny_colden_5273.zip",
                        "CVE-2017-12635_6/test/normal_and_attack/screeching_bhaskara_5377.zip",
                        "CVE-2020-9484/training/cool_gates_5400.zip",
                        "CVE-2020-13942/training/colossal_shirley_6529.zip",
                        "CVE-2020-13942/training/cool_mendel_2541.zip",
                        "CVE-2020-13942/training/cool_roentgen_6530.zip",
                        "CVE-2020-13942/test/normal_and_attack/cool_keller_3507.zip",
                        "CVE-2020-13942/test/normal_and_attack/cool_kilby_2364.zip",
                        "CVE-2020-13942/training/colossal_merkle_7294.zip"]

if __name__ == '__main__':
    # base_path
    base_path = "/home/grimmer/Work/LID-DS-2021/"
    # delete all
    for file in list_of_defect_files:
        file_to_remove = os.path.join(base_path, file)
        print(f"remove {file_to_remove}")
        os.remove(file_to_remove)

    # load json file
    with open("defect_files.json") as f:
        data = json.load(f)

    for scenario in data.keys():
        print(f" in {scenario}:")
        for section in data[scenario]:
            print(f"   in {section}:")
            for runtype in data[scenario][section]:
                print(f"      in {runtype}: ")
                for file in data[scenario][section][runtype]:
                    file_to_remove = os.path.join(base_path, file)
                    print(f"remove {file_to_remove}")
                    os.remove(file_to_remove)
