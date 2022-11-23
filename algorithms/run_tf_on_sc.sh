#!/bin/bash
#SBATCH --partition=paula
#SBATCH --time=24:00:00
#SBATCH --cpus-per-task=4
#SBATCH --mem=50GB
#SBATCH --gres=gpu:a30
#SBATCH --mail-type=FAIL
#SBATCH -o logs/job_%A_%a.log

export IDS_ON_CLUSTER=1

module load matplotlib
module load CUDA/11.3.1

pip install --upgrade pip
python -c "import algorithms"
module_missing=$?
if [$module_missing]
then
       pip install --user -e ../
fi
pip install --user torch --extra-index-url https://download.pytorch.org/whl/cu116
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
# 10: -h num_heads
# 11: -lm language_model
python ids_transformer_main.py -d "$1" -v "$2" -s "$3" -c "$4" -n "$5" -t "$6" -f "$7" -l "$8" -m "$9" -h "${10}" -lm "${11}"
