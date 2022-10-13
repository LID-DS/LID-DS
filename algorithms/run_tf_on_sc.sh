#!/bin/bash
#SBATCH --partition=paula
#SBATCH --time=8:00:00
#SBATCH --mem=8G
#SBATCH --cpus-per-tasks=4
#SBATCH --mem-per-gpu=6GB
#SBATCH --gres=gpu:a30
#SBATCH --mail-type=FAIL

export IDS_ON_CLUSTER=1

module load matplotlib
pip install --upgrade pip
pip install --user -e ../
pip install --user -r ../requirements.txt

# parameters:
# 1: -d base_path
# 2: -v lid_ds_version
# 3: -s scenario_name
# 4: -c checkpoint_dir
# 5: -n ngram_length
# 6: -t thread_aware
# 7: -f feedforward_dim
# 8: -l layers
# 9: -m model_dim
python ids_transformer_main.py -d "$1" -v "$2" -s "$3" -c "$4" -n "$5" -t "$6" -f "$7" -l "$8" -m "$9"
