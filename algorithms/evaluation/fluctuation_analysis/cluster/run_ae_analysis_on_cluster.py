"""
script to start multiple jobs in cluster
"""
import os
import time

scenario_2019 = [
    "CVE-2017-7529",
    "CVE-2014-0160",
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "SQL_Injection_CWE-89",
    "PHP_CWE-434",

    # "EPS_CWE-434",
    # "ZipSlip",
]

scenario_2021 = [
    "CVE-2017-7529",
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2014-0160",
    "PHP_CWE-434",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "CWE-89-SQL-injection",
    "CVE-2020-23839",

    # "CVE-2020-9484",
    # "EPS_CWE-434",
    # "Juice-Shop"
    # "CVE-2020-13942",
    # "CVE-2017-12635_6",
    # "ZipSlip",
]

EVALUATE = False
# EVALUATE = True

eval_after_load = True
custom_splits = [True, False]
USER = "ta651pyga"
DATASET = "LID-DS-2019"
CHECKPOINT_DIR = f"/work/users/{USER}/final/fluctuation_analysis/"
NGRAM_LENGTHS = [8, 16, 32]
DROPOUTS = [0.05, 0.1, 0.3, 0.5]

BASE_PATH = f"/work/users/{USER}/datasets/{DATASET}/"
if '2019' in BASE_PATH:
    SCENARIOS = scenario_2019
else:
    SCENARIOS = scenario_2021

MAX_JOBS_IN_QUEUE = 600
NUM_EXPERIMENTS = 0


def count_queue():
    """
    counts the number of my jobs in the queue
    """
    return int(os.popen(f"squeue -u {USER} | wc -l").read().strip("\n")) - 1


def start_job(job_str):
    """
    starts the job given by str
    if the number of my jobs in the queue is smaller than MAX_JOBS_IN_QUEUE
    """
    while True:
        time.sleep(0.5)
        # get the number of jobs in the queue
        count = count_queue()
        if count < MAX_JOBS_IN_QUEUE:
            print(job_str)
            os.system(job_str)
            print(f"there are {count} jobs in queue")
            break


# start jobs for specific configuration
if not EVALUATE:
    SCRIPT = 'run_ae_on_sc_cpu.sh'
    for scenario in SCENARIOS:
        for ngram_length in NGRAM_LENGTHS:
            NUM_EXPERIMENTS += 1
            command = f"sbatch --job-name=ex_{NUM_EXPERIMENTS:05}{scenario}n{ngram_length}eal{eval_after_load} " + \
                      f"{SCRIPT} " + \
                      f"{BASE_PATH} " + \
                      f"{DATASET} " + \
                      f"{scenario} " + \
                      f"{CHECKPOINT_DIR} " + \
                      f"{ngram_length} " + \
                      f"{eval_after_load} " + \
                      f"False "

            start_job(command)
else:
    SCRIPT = 'run_ae_on_sc.sh'
    for dropout in DROPOUTS:
        for custom_split in custom_splits:
            for scenario in SCENARIOS:
                for ngram_length in NGRAM_LENGTHS:
                    NUM_EXPERIMENTS += 1
                    command = f"sbatch --job-name=ex_{NUM_EXPERIMENTS:05}{scenario}n{ngram_length}c{custom_split}eal{eval_after_load}do{dropout} " + \
                              f"{SCRIPT} " + \
                              f"{BASE_PATH} " + \
                              f"{DATASET} " + \
                              f"{scenario} " + \
                              f"{CHECKPOINT_DIR} " + \
                              f"{ngram_length} " + \
                              f"{custom_split} " + \
                              f"{eval_after_load} " + \
                              f"{dropout} " + \
                              f"True "

                    start_job(command)

print(f"NUM_EXPERIMENTS = {NUM_EXPERIMENTS}")
