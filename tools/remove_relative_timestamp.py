import os
import zipfile

import json

from tqdm import tqdm

from dataloader.data_loader import DataLoader

SCENARIO_NAMES = [
    # "Bruteforce_CWE-307",
    # "CVE-2012-2122",
    # "CVE-2014-0160",
    # "CVE-2017-7529",
    # "CVE-2017-12635_6",
    # "CVE-2018-3760",
    # "CVE-2019-5418",
    # "CVE-2020-9484",
    # "CVE-2020-13942",
    # "CVE-2020-23839",
    "CWE-89-SQL-injection",
    "EPS_CWE-434",
    "Juice-Shop",
    "PHP_CWE-434",
    "ZipSlip"
]


if __name__ == '__main__':

    dataset_base_path = '/home/felix/repos/LID-DS/LID-DS-2021/'
    categories = ['training', 'test', 'validation']
    target_dir = '/media/felix/PortableSSD/LID-DS-2021-clean'
    subcategories = ['normal', 'normal_and_attack']
    times = ['container_ready', 'warmup_end']

    for scenario in tqdm(SCENARIO_NAMES):
        dataloader = DataLoader(os.path.join(dataset_base_path, scenario))
        for category in tqdm(categories):
            for recording in dataloader.extract_recordings(category):
                recording_path = recording.path
                sub_path = recording.path.replace(dataset_base_path, '')
                src_zip = recording_path
                dst_zip = os.path.join(target_dir, sub_path)
                recording_name = os.path.splitext(os.path.basename(os.path.normpath(recording_path)))[0]
                scenario_name = sub_path.split('/')[0]
                try:
                    os.mkdir(os.path.join(target_dir, scenario_name))
                except FileExistsError:
                    pass

                for dir_name in categories:
                    try:
                        os.mkdir(os.path.join(target_dir, scenario_name, dir_name))
                    except FileExistsError:
                        pass

                for dir_name in subcategories:
                    try:
                        os.mkdir(os.path.join(target_dir, scenario_name, 'test', dir_name))
                    except FileExistsError:
                        pass

                with zipfile.ZipFile(src_zip) as inzip, zipfile.ZipFile(dst_zip, "w",
                                                                        zipfile.ZIP_DEFLATED,
                                                                        compresslevel=8) as outzip:
                    # Iterate the input files
                    for inzipinfo in inzip.infolist():
                        with inzip.open(inzipinfo) as infile:
                            if inzipinfo.filename == f'{recording_name}.json':
                                content = json.loads(infile.read().decode('utf-8'))
                                for time in times:
                                    del content['time'][time]['relative']
                                for exploit in content['time']['exploit']:
                                    del exploit['relative']
                                outzip.writestr(inzipinfo.filename, json.dumps(content, indent=4))
                            else:
                                content = infile.read()
                                outzip.writestr(inzipinfo.filename, content)

