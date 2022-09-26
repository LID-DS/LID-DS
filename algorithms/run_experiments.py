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
epochs = 20
windows = [1000]
batch_sizes = [1024]
embedding_sizes = [1]
ngram_lengths = [5]
thread_aware_list = [True]
time_deltas = [False]
thread_change_flags = [False]
return_values = [False]
# base_path = '/work/user/te697mily/Data/'
# base_path = '/work/user/te697mily/Data/LID-DS-2019/'
base_path = '../../Data/LID-DS-2019/'
if '2019' in base_path:
    scenarios = scenario_2019 
else:
    scenarios = scenario_2021 
script = '/home/sc.uni-leipzig.de/te697mily/LID-DS/algorithms/run_on_sc.sh'

max_jobs_in_queue = 1000
num_experiments = 0


# counts the number of my jobs in the queue
def count_queue(): 
    user = "te697mily"
    return int(os.popen(f"squeue -u {user} | wc -l").read().strip("\n")) - 1

# starts the job given by str
# if the number of my jobs in the queue is smaller than max_jobs_in_queue
def start_job(str):
    while True:
        time.sleep(0.5)
        # get the number of jobs in the queue
        count = count_queue()
        print(f"there are {count} jobs in queue")
        if count < max_jobs_in_queue:
            print(str)
            os.system(str)
            break


# start jobs for specific configuration
for thread_aware in thread_aware_list:
    for batch_size in batch_sizes:
        for embedding_size in embedding_sizes:
            for time_delta in time_deltas:
                for thread_change_flag in thread_change_flags:
                    for return_value in return_values:
                        for ngram_length in ngram_lengths:
                            for window in windows:
                                for scenario in scenarios:
                                    num_experiments += 1
                                    command = f"sbatch --job-name=ex_{num_experiments:05} {script} {base_path} {scenario} {batch_size} {epochs} {embedding_size} {ngram_length} {window} {thread_change_flag} {return_value}"
                                    print(command)
                                    start_job(command)

print("num_experiments = {}".format(num_experiments))
