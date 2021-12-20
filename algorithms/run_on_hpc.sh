#!/bin/bash
#SBATCH --time=40:00:00
#SBATCH --partition=clara-job
#SBATCH --gres=gpu:rtx2080ti:1
#SBATCH --mem=80G

# source /scratch/ws/1/tikl664d-master/master/bin/activate
# module load Python
module load Python/3.7.4-GCCcore-8.3.0
# module load PyTorch/1.8.1-fosscuda-2019b-Python-3.7.4
module load PyTorch/1.9.0-fosscuda-2020b
module load matplotlib
# module load networkx/2.5-fosscuda-2020b
# module load networkx/2.4-fosscuda-2019b-Python-3.7.4
# module load networkx/2.5-foss-2020b

pip install --upgrade pip
pip install --user -e ../
pip install --user nest-asyncio
pip install --user pypcapkit
pip install --user networkx
pip install --user pydot
pip install --user gensim==4.1.2


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
# srun python lstm_cluster_main.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 $flags
srun python test.py
