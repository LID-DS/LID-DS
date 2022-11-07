#!/bin/bash
#SBATCH --partition=paula-gpu
#SBATCH --time=10:00:00
#SBATCH --mem=64G

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

echo $1
python ids_cluster.py -d $1 -s $2 -b $3 -ep $4 -e $5 -n $6 -w $7
