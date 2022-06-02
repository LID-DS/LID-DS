import os
import time

scenarios = [
    #"Bruteforce_CWE-307/",
    "CVE-2012-2122/",
    "CVE-2014-0160/",
    # "CVE-2017-7529/",
    # "CVE-2018-3760/",
    # "CVE-2019-5418/",
    # "EPS_CWE-434/",
    # "PHP_CWE-434/",
    # "SQL_Injection_CWE-89/"
    # "ZipSlip/"
]

epochs = 20
batch_sizes = [1024]
embedding_sizes = ["8", "6", "4"]
ngram_lengths = ["6", "2"]
thread_aware_list = ["True"]
time_deltas = ["True", "False"]
thread_change_flags = ["True", "False"]
return_values = ["True", "False"]
# base_path = '/home/tikl664d/projects/p_madgan/ws_link/scratch/tikl664d-test-workspace/Dataset2019/'
base_path = '/home/sc.uni-leipzig.de/te697mily/master/Praxis/Data/'

# script = "/home/tikl664d/projects/p_madgan/ws_link/scratch/tikl664d-test-workspace/LID-DS/algorithms/run_hpc.sh"
script = '/home/sc.uni-leipzig.de/te697mily/master/Praxis/LID-DS/algorithms/run_on_hpc.sh'

max_jobs_in_queue = 100
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

num_experiments += 1
scenario = scenarios[1]
batch_size = 1024
epochs = 20
ngram_length = 6
embedding_size = 8
return_value = "True"
thread_change_flag = "True"
time_delta = "True"
command = f"sbatch --job-name=ex_{num_experiments:05} {script} {base_path} {scenario} {batch_size} {epochs} {embedding_size} {ngram_length} {time_delta} {thread_change_flag} {return_value}"
print(command)
start_job(command)

print("num_experiments = {}".format(num_experiments))
