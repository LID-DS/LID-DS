import argparse
import json

import matplotlib.pyplot as plt
import numpy as np

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

    parser.add_argument('-d', dest='path', action='store', type=str, required=True,
                        help='syscall stats file to plot')
    parser.add_argument('-ni', dest='no_idle', action='store_true', help='exclude idle runs', default=False)
    parser.add_argument('-nao', dest='no_attack_only', action='store_true', help='exclude attack only runs',
                        default=False)

    args = parser.parse_args()

    plt.close("all")

    fig, axes = plt.subplots()

    with open(args.path) as json_file:
        data_dict = json.load(json_file)

    scenario = list(data_dict.keys())[0]

    syscall_names = list(data_dict[scenario]['Test']['Normal and Attack']['syscall_distribution'].keys())

    plot_data_dict = {}

    for sub_set in data_dict[scenario].keys():
        for run_type in data_dict[scenario][sub_set].keys():
            if args.no_idle and run_type == 'Idle':
                pass
            elif args.no_attack_only and run_type == 'Attack':
                pass
            else:
                total_syscall_count = 0
                for syscall in data_dict[scenario][sub_set][run_type]['syscall_distribution'].keys():
                    total_syscall_count += data_dict[scenario][sub_set][run_type]['syscall_distribution'][syscall]

                plot_data_dict[f'{sub_set} {run_type}'] = []
                for syscall in syscall_names:
                    if syscall in data_dict[scenario][sub_set][run_type]['syscall_distribution'].keys():
                        proportion = data_dict[scenario][sub_set][run_type]['syscall_distribution'][
                                         syscall] / total_syscall_count
                        plot_data_dict[f'{sub_set} {run_type}'].append(proportion)
                    else:
                        plot_data_dict[f'{sub_set} {run_type}'].append(0)

    x = np.arange(len(syscall_names))

    width = 0.09

    bar_count = len(list(data_dict.keys()))

    current_bar = -(0.5 * bar_count)
    for key in plot_data_dict.keys():
        axes.bar(x + current_bar * 0.1, plot_data_dict[key], width, label=key)
        current_bar += 1

    plt.xticks(x, syscall_names, rotation=45)
    axes.legend()

    plt.suptitle(f'{scenario} System Call Comparison')
    plt.xlabel('System Calls')
    plt.ylabel('Proportion')

    plt.show()
