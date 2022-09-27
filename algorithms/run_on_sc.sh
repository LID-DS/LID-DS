#!/bin/bash
#SBATCH --partition=paula-gpu
#SBATCH --time=10:00:00
#SBATCH --mem=64G

module load matplotlib
pip install --upgrade pip
pip install --user -e ../
pip install --user -r ../requirements.txt

# parameters:
# 1: base_path
# 2: scenario_name
# 3: embedding_size
# 4: ngram_length
# 5: window
# 6: thread_aware 

python ids_cluster.py -d $1 -s $2 -e $3 -n $4 -w $5 -ta $6
