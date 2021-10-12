import json
import os

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
    base_path = "/home/recording/LID-DS-2021/"
    # python command
    python_cmd = "python3"

    # load json file
    with open("defect_files.json") as f:
        data = json.load(f)

    for scenario in data.keys():
        print(f"cd {os.path.join(base_path, scenario)}")
        for section in data[scenario]:
            for runtype in data[scenario][section]:
                count = 0
                for file in data[scenario][section][runtype]:
                    count += 1
                if count > 0:
                    print(f"# {scenario}/{section}/{runtype}: {count}")
                    extra = ""
                    if scenario == "CVE-2012-2122":
                        extra = "n 1"
                    if scenario == "CVE-2017-12635_6":
                        extra = "1"
                    if scenario == "CVE-2020-13942":
                        extra = "ognl"  # ognl / mvel
                    if scenario == "Juice-Shop":
                        extra = "SQLInjectionSchema"  #SQLInjectionSchema, SQLInjectionCred, SQLInjectionUser
                    for i in range(count):
                        if section == "Training":
                            if runtype == "Normal":
                                print(f"{python_cmd} main.py 1 45 0")
                            if runtype == "Idle":
                                print(f"{python_cmd} main.py 0 45 0")
                        if section == "Validation":
                            if runtype == "Normal":
                                print(f"{python_cmd} main.py 1 45 0")
                            if runtype == "Idle":
                                print(f"{python_cmd} main.py 0 45 0")
                        if section == "Test":
                            if runtype == "Normal":
                                print(f"{python_cmd} main.py 1 45 0")
                            if runtype == "Idle":
                                print(f"{python_cmd} main.py 0 45 0")
                            if runtype == "Normal and Attack":
                                print(f"{python_cmd} main.py 1 -1 1 {extra}")
                            if runtype == "Attack":
                                print(f"{python_cmd} main.py 0 -1 1 {extra}")

