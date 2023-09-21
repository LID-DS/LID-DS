#!/bin/bash
#SBATCH --partition=clara
#SBATCH --time=2-00:00:00
#SBATCH --cpus-per-task=2
#SBATCH --mem=40GB
#SBATCH --gres=gpu:v100
#SBATCH --mail-type=FAIL
#SBATCH -o logs/tf/job_eval_%A_%a.log

export IDS_ON_CLUSTER=1

module load matplotlib/3.4.3-foss-2021b
module load CUDA/11.3.1
module load Python/3.9.6-GCCcore-11.2.0
module load SciPy-bundle/2021.10-foss-2021b
module load PyTorch/1.10.0-foss-2021a-CUDA-11.3.1
module load tensorboard/2.8.0-foss-2021a

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
# 6: -l layers
# 7: -m model_dim
# 8: -nh num_heads
# 9: -cs custom_split
# 10: -do dropout
# 11: -e evaluate
python fluctuation_analysis_tf.py -bp "$1" -v "$2" -s "$3" -c "$4" -n "$5" -l "$6" -m "$7" -nh "$8" -cs "$9" -do "${10}" -e "${11}"
