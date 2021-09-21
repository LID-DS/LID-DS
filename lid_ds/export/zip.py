import glob
import json
import os
import sys
from enum import Enum
import zipfile


def zip_files(json_file):
    # get the file names
    json_base_name = os.path.basename(json_file)
    dir_name = os.path.dirname(json_file)
    run_name = os.path.splitext(json_base_name)[0]

    sc_name = os.path.join(dir_name, run_name) + ".sc"
    pcap_name = os.path.join(dir_name, run_name) + ".pcap"
    res_name = os.path.join(dir_name, run_name) + ".res"

    zip_name = os.path.join(dir_name, run_name) + ".zip"

    zfile = zipfile.ZipFile(zip_name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=8)
    zfile.write(json_file, f"{run_name}.json")
    zfile.write(sc_name, f"{run_name}.sc")
    zfile.write(pcap_name, f"{run_name}.pcap")
    zfile.write(res_name, f"{run_name}.res")
    zfile.close()


if __name__ == '__main__':

    path = sys.argv[1]
    print(f"working on: {path}")

    # get all json files
    list_of_jsons = [f for f in glob.glob(path + "/*.json")]

    # iterate over all json files, zip them with their corresponding files
    counter = 0
    amount = len(list_of_jsons)
    for file in list_of_jsons:
        zip_files(file)
        counter += 1
        print(f" -- at {counter / amount * 100.0}% --")
