"""
script to start multiple jobs in cluster
"""
import os
import time

scenario_2019 = [
    # "Bruteforce_CWE-307/",
    # "CVE-2012-2122/",
    # "CVE-2014-0160/",
    "CVE-2017-7529/",
    # "CVE-2018-3760/",
    # "CVE-2019-5418/",
    # "SQL_Injection_CWE-89/",
    # "EPS_CWE-434/",
    # "PHP_CWE-434/",
    # "ZipSlip/",
]

scenario_2021 = [
    "Bruteforce_CWE-307/",
    "CVE-2012-2122/",
    "CVE-2014-0160/",
    "CVE-2017-12635_6/",
    "CVE-2017-7529/",
    "CVE-2018-3760/",
    "CVE-2019-5418/",
    "CVE-2020-13942/",
    "CVE-2020-23839/",
    "CVE-2020-9484/",
    "CWE-89-SQL-injection",
    "EPS_CWE-434/",
    "Juice-Shop/"
    "PHP_CWE-434/",
    "ZipSlip/",
    # "real_world/"
]
EPOCHS = 20
WINDOWS = [1000]
BATCH_SIZES = [1024]
EMBEDDING_SIZES = [1]
NGRAM_LENGTHS = [5]
THREAD_AWARE_LIST = [True]

# base_path = '/work/user/te697mily/Data/'
# base_path = '/work/user/te697mily/Data/LID-DS-2019/'
BASE_PATH = '../../Data/LID-DS-2019/'
if '2019' in BASE_PATH:
    scenarios = scenario_2019
else:
    scenarios = scenario_2021
SCRIPT = '/home/sc.uni-leipzig.de/te697mily/LID-DS/algorithms/run_on_sc.sh'

MAX_JOBS_IN_QUEUE = 1000
NUM_EXPERIMENTS= 0


def count_queue():
    """
    counts the number of my jobs in the queue
    """
    user = "te697mily"
    return int(os.popen(f"squeue -u {user} | wc -l").read().strip("\n")) - 1

def start_job(job_str):
    """
    starts the job given by str
    if the number of my jobs in the queue is smaller than MAX_JOBS_IN_QUEUE
    """
    while True:
        time.sleep(0.5)
        # get the number of jobs in the queue
        count = count_queue()
        print(f"there are {count} jobs in queue")
        if count < MAX_JOBS_IN_QUEUE:
            print(job_str)
            os.system(job_str)
            break


# start jobs for specific configuration
for thread_aware in THREAD_AWARE_LIST:
    for embedding_size in EMBEDDING_SIZES:
        for ngram_length in NGRAM_LENGTHS:
            for window in WINDOWS:
                for scenario in scenarios:
                    NUM_EXPERIMENTS += 1
                    command = f"sbatch --job-name=ex_{NUM_EXPERIMENTS:05}" + \
                               "{script}" + \
                               "{base_path}" + \
                               "{scenario}" + \
                               "{ngram_length}" + \
                               "{window}"
                    print(command)
                    start_job(command)

print(f"NUM_EXPERIMENTS = {NUM_EXPERIMENTS}")
