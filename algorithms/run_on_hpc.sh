#!/bin/bash
#SBATCH --partition=ml     
#SBATCH --gres=gpu:1           # use 1 GPU per node 
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1    # limit to one node
#SBATCH --cpus-per-task=16     # use 16 threads per task
#SBATCH --mem=32000M           # total memory
#SBATCH -J lids_lstm_training  # job name
#SBATCH --time=20:00:00        # run for 1 hour

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

time_delta_flag=" -td"
thread_change_flag=" -tcf"
return_value_flag=" -rv"
flags=""
if [ $7 == "True" ]; then
    flags="$flags$time_delta_flag"
fi
if [ $8 == "True" ]; then
    flags="$flags$thread_change_flag"
fi
if [ $9 == "True" ]; then
    flags="$flags$return_value_flag"
fi
echo $flags
srun python hpc_ids_lstm_main.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 $flags
