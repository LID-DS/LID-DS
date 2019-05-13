import os

def add_run(scenario):
    out_dir = os.environ.get('LIDDS_OUT_DIR', '.')
    runs_runs_file_path = os.path.join(out_dir, "runs.csv")
    if os.path.isfile(runs_runs_file_path):
        runs_file = open(runs_runs_file_path, "a+")
    else:
        runs_file = open(runs_runs_file_path, "w+")
        _write_runs_header(runs_file)
    _write_run_for_scenario(scenario, runs_file)
    runs_file.close()

def _write_run_for_scenario(scenario, runs_file):
    if scenario.execute_exploit:
        runs_file.write("{}, {}, {}, {}, {}, {}\n".format(scenario.image_name, scenario.name, str(scenario.execute_exploit), str(scenario.warmup_time), str(scenario.recording_time), str(scenario.exploit_start_time)))
    else:
        runs_file.write("{}, {}, {}, {}, {}, {}\n".format(scenario.image_name, scenario.name, str(scenario.execute_exploit), str(scenario.warmup_time), str(scenario.recording_time), -1))

def _write_runs_header(runs_file):
    runs_file.write("{}, {}, {}, {}, {}, {}\n".format(
            'image_name',
            'scenario_name',
            'is_executing_exploit',
            'warmup_time',
            'recording_time',
            'exploit_start_time'
    ))