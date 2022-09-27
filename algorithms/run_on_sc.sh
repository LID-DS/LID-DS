#!/bin/bash
#SBATCH --partition=paula-gpu
#SBATCH --time=10:00:00
#SBATCH --mem=64G

module load matplotlib
pip install --upgrade pip
pip install --user -e ../
pip install --user -r ../requirements.txt

# parameters:
# 1: -d base_path
# 2: -s scenario_name
# 3: -e embedding_size
# 4: -n ngram_length
# 5: -w window
# 6: -ta thread_aware 
python ids_cluster.py -d $1 -s $2 -e $3 -n $4 -w $5 -t $6
