#!/bin/bash
#SBATCH --array 0-1
#SBATCH --ntasks=2
#SBATCH --cpus-per-task=4      # use 16 threads per task
#SBATCH --gres=gpu:2           # use 1 GPU per node 
#SBATCH --gpus-per-task=1      # use 16 threads per task
#SBATCH --time=20:00:00        # run for 1 hour
#SBATCH --mem-per-cpu=1443     # total memory
#SBATCH -J lids_lstm_training  # job name
#SBATCH --partition=ml     

source /scratch/ws/1/tikl664d-master/master/bin/activate
module purge
module load modenv/ml torchvision/0.7.0-fosscuda-2019b-Python-3.7.4-PyTorch-1.6.0

# parameters:
# 1: base_path
# 2: scenario_name
# 3: batch_size
# 4: epochs
# 5: embedding_size
# 6: ngram_length
# 7: time_delta
# 8: thread_change_flag
# 9: return_value
ntasks=1
scenarios=("CVE-2017-7529/")
batch_sizes=("1024")
embedding_sizes=("4") # "8")
ngram_lengths=("4") # "6")
thread_aware_list=("True")
time_deltas=("False") # "True")
thread_change_flags=("False") # "True")
return_values=("False" "True")
base_path="/home/tikl664d/projects/p_madgan/ws_link/scratch/tikl664d-test-workspace/Dataset2019/"
script="/home/tikl664d/projects/p_madgan/ws_link/scratch/tikl664d-test-workspace/LID-DS/algorithms/run_on_hpc.sh"

count_queue (){
    user="tikl664d"
    counter=$(squeue -u $user | wc -l)
    counter=$(($counter - 1))
    echo $counter
}
epochs=20

job_array=()
for batch in ${batch_sizes[@]}; do
    for embedding_size in ${embedding_sizes[@]}; do
        for thread_aware in ${thread_aware_list[@]}; do
            for time_delta in ${time_deltas[@]}; do
                for thread_change_flag in ${thread_change_flags[@]}; do
                    for return_value in ${return_values[@]}; do
                        for ngram_length in ${ngram_lengths[@]}; do
                            for scenario in ${scenarios[@]}; do
                                time_delta_flag=" -td"
                                thread_change_flag_flag=" -tcf"
                                return_value_flag=" -rv"
                                flags=""
                                if [ $time_delta == "True" ]; then
                                    flags="$flags$time_delta_flag"
                                fi
                                if [ $thread_change_flag == "True" ]; then
                                    flags="$flags$thread_change_flag_flag"
                                fi
                                if [ $return_value == "True" ]; then
                                    flags="$flags$return_value_flag"
                                fi
                                echo $flags
                                com="srun --exclusive \
                                    --gres=gpu:1 \
                                    --ntasks=1 \
                                    --cpus-per-task=4 \
                                    --gpus-per-task=1 \
                                    --mem-per-cpu=1443 \
                                    python lstm_cluster_main.py \
                                    -d $base_path \
                                    -s $scenario \
                                    -b $batch \
                                    -ep $epochs \
                                    -e $embedding_size \
                                    -n $ngram_length \
                                    $flags"
                                job_array+=("$com")
                                #while true
                                #do
                                    #sleep 5
                                    #count=$(count_queue)
                                    #echo "there are "$count" jobs in queue"
                                    #if [[ "$count" -lt "$ntasks" ]]
                                    #then
                                        #eval $com
                                        #break
                                    #fi
                                #done
                            done
                        done
                    done
                done
            done
        done
    done
done
eval "${job_array[$SLURM_ARRAY_TASK_ID]}"
