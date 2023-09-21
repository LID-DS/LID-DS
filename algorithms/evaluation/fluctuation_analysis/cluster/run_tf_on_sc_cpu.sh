#!/bin/bash
#SBATCH --partition=paul
#SBATCH --time=2-00:00:00
#SBATCH --cpus-per-task=1
#SBATCH --mem=30GB
#SBATCH --mail-type=FAIL
#SBATCH -o logs/tf/job_train_%A_%a.log

export IDS_ON_CLUSTER=1

module load matplotlib/3.4.3-foss-2021b
module load CUDA/11.3.1
module load Python/3.9.6-GCCcore-11.2.0
module load SciPy-bundle/2021.10-foss-2021b
module load PyTorch/1.12.1-foss-2022a-CUDA-11.7.0

#pip install --upgrade pip
#python -c "import algorithms"
#module_missing=$?
#if [ $module_missing -ne 0 ]; then
#  pip install --user -e ../
#fi
#pip install --user -r "$(grep -ivE 'torch' ../requirements.txt)"

export PYTHONPATH="/home/sc.uni-leipzig.de/ta651pyga/lidds_wt/thesis/LID-DS:$PYTHONPATH"

# parameters:
# 1: -bp base_path
# 2: -ds dataset
# 3: -s scenario_name
# 4: -c checkpoint_dir
# 5: -n ngram_length
# 6: -e evaluate
python fluctuation_analysis_tf.py -bp "$1" -v "$2" -s "$3" -c "$4" -n "$5" -e "$6"
