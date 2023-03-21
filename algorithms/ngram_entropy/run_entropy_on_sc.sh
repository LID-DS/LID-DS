#!/bin/bash
#SBATCH --partition=paul
#SBATCH --time=2-00:00:00
#SBATCH --cpus-per-task=1
#SBATCH --mem=30GB
#SBATCH --mail-type=FAIL
#SBATCH -o logs/entropy/job_%A_%a.log

export IDS_ON_CLUSTER=1

module load matplotlib/3.4.3-foss-2021b
module load CUDA/11.3.1
module load Python/3.9.6-GCCcore-11.2.0
module load SciPy-bundle/2021.10-foss-2021b

pip install --upgrade pip
python -c "import algorithms"
module_missing=$?
if [ $module_missing -ne 0 ]; then
  pip install --user -e ../../
fi
pip install --user torch --extra-index-url https://download.pytorch.org/whl/cu116
#pip install --user -r "$(grep -ivE 'torch' ../../requirements.txt)"

# parameters:
# 1: -d base_path
# 2: -v lid_ds_version
# 3: -s scenario_name
# 4: -c checkpoint_dir
# 5: -n ngram_length
# 6: -direction
python entropy_main.py -d "$1" -v "$2" -s "$3" -c "$4" -n "$5" -direction "$6"
