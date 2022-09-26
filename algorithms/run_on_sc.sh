#!/bin/bash
#SBATCH --partition=paula-gpu
#SBATCH --time=10:00:00
#SBATCH --mem=64G

# module load PyTorch/1.8.1-fosscuda-2020b

module load matplotlib
pip install --upgrade pip
pip install --user -e ../
pip install --user -r ../requirements.txt
pip install --user tqdm
pip install --user minisom


# parameters:
# 1: base_path
# 2: scenario_name
# 3: batch_size
# 4: epochs
# 5: embedding_size
# 6: ngram_length
# 7: window
# 8: thread_change_flag
# 9: return_value

thread_change_flag=" -tcf"
return_value_flag=" -rv"
flags=""
if [[ $8 == "True" ]]; then
    flags="$flags$thread_change_flag"
fi
if [[ $9 == "True" ]]; then
    flags="$flags$return_value_flag"
fi
echo $1
# python ae_ids_cluster.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 -w $7 $flags
python ids_cluster.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 -w $7 $flags
# python stide_ids_cluster.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 -w $7 $flags
# python test_map_reduce.py
