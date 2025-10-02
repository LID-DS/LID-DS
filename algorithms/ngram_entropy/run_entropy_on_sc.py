"""
script to start multiple jobs in cluster
"""
import os
import time

scenario_2019 = [
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2014-0160",
    "CVE-2017-7529",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "PHP_CWE-434",
    "SQL_Injection_CWE-89",
    "EPS_CWE-434",
    "ZipSlip",
]

scenario_2021 = [
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2014-0160",
    "CVE-2017-12635_6",
    "CVE-2017-7529",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "CVE-2020-13942",
    "CVE-2020-23839",
    "CVE-2020-9484",
    "CWE-89-SQL-injection",
    "EPS_CWE-434",
    "Juice-Shop"
    "PHP_CWE-434",
    "ZipSlip",
]

USER = "ta651pyga"
DATASET = "LID-DS-2019"
CHECKPOINT_DIR = f"/work/users/{USER}/entropy"
NGRAM_LENGTHS = range(2, 35)
DIRECTIONS = ['open', 'both']

BASE_PATH = f"/work/users/{USER}/datasets/"

if '2019' in DATASET:
    SCENARIOS = scenario_2019
else:
    SCENARIOS = scenario_2021
SCRIPT = 'run_entropy_on_sc.sh'

MAX_JOBS_IN_QUEUE = 500
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


for scenario in SCENARIOS:
    for ngram_length in NGRAM_LENGTHS:
        for direction in DIRECTIONS:
            NUM_EXPERIMENTS += 1
            command = f"sbatch --job-name=ex_{NUM_EXPERIMENTS:05}{scenario}n{ngram_length} " \
                      f"{SCRIPT} " \
                      f"{BASE_PATH} " \
                      f"{DATASET} " \
                      f"{scenario} " \
                      f"{CHECKPOINT_DIR} " \
                      f"{ngram_length} " \
                      f"{direction}"

            start_job(command)

print(f"started {NUM_EXPERIMENTS} experiments")
