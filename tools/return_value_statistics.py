from dataloader.syscall import Direction
from dataloader.recording_2019 import RecordingDataParts
from dataloader.dataloader_factory import dataloader_factory

from tqdm import tqdm

if __name__ == '__main__':

    SCENARIO_NAMES = [
        "Bruteforce_CWE-307",
        "CVE-2012-2122",
        "CVE-2014-0160",
        "CVE-2017-7529",
        "CVE-2018-3760",
        "CVE-2019-5418",
        # "PHP_CWE-434",
        # "EPS_CWE-434",
        # "ZipSlip"
    ]
    # iterates through list of all scenarios, main loop
    for scenario in tqdm(SCENARIO_NAMES):
        # scenario = 'CVE-2017-7529'
        dataloader = dataloader_factory(f'../../Dataset/{scenario}/', Direction.CLOSE)
        distinct_syscalls = {}

        # dict to describe dataset structure
        data_parts = {
            'Training': dataloader.training_data(),
            'Validation': dataloader.validation_data(),
            'Test': dataloader.test_data()
        }
        for data_part in data_parts.keys():
            for recording in tqdm(data_parts[data_part], f'{scenario}: {data_part}'.rjust(45), unit=" recordings", smoothing=0):
                for syscall in recording.syscalls():
                    return_value_string = syscall.param('res')
                    if return_value_string:
                        if syscall.name() not in distinct_syscalls.keys():
                            distinct_syscalls[syscall.name()] = 1
    print(distinct_syscalls)
