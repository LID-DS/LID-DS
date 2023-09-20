#!/bin/bash
#SBATCH --partition=paula
#SBATCH --time=2-00:00:00
#SBATCH --cpus-per-task=2
#SBATCH --mem=30GB
#SBATCH --gres=gpu:a30
#SBATCH --mail-type=FAIL
#SBATCH -o logs/job_train_%A_%a.log

export IDS_ON_CLUSTER=1

module load matplotlib/3.4.3-foss-2021b
module load CUDA/11.3.1
module load Python/3.9.6-GCCcore-11.2.0
module load SciPy-bundle/2021.10-foss-2021b

pip install --upgrade pip
python -c "import algorithms"
module_missing=$?
if [ $module_missing -ne 0 ]; then
  pip install --user -e ../
fi
pip install --user torch --extra-index-url https://download.pytorch.org/whl/cu116
pip install --user -r "$(grep -ivE 'torch' ../requirements.txt)"

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
# 10: -nh num_heads
# 11: -lm language_model
# 12: -b batch_size
# 13: -dup dedup_train_set
# 14: -as anomaly_score
# 15: -ret use_return_value
# 16: -pname process_name
# 17: -paths use_paths
# 18: -time time_delta
# 19: -run run number (for multiple runs)
python ids_transformer_main.py -d "$1" -v "$2" -s "$3" -c "$4" -n "$5" -t "$6" -f "$7" -l "$8" -m "$9" -nh "${10}" -lm "${11}" -b "${12}" -dup "${13}" -as "${14}" -ret "${15}" -pname "${16}" -paths "${17}" -time "${18}" -run "${19}" -eval "False" -e 900