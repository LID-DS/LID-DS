import argparse
import json

import matplotlib.pyplot as plt
import pandas as pd

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021 Syscalls')

    parser.add_argument('-d', dest='path', action='store', type=str, required=True,
                        help='syscall stats file to plot')
    args = parser.parse_args()

    plt.close("all")

    data_dict = None
    key = None
    with open(args.path) as json_file:
        data_dict = json.load(json_file)

    if 'syscall_distribution' in json.dumps(data_dict):
        key = 'syscall_distribution'
    elif 'protocol_distribution' in json.dumps(data_dict):
        key = 'protocol_distribution'

    fig, axes = plt.subplots(nrows=3, ncols=4)

    scenario_name = None

    if data_dict is not None and key is not None:
        for scenario in data_dict.keys():
            print("  " + scenario)
            scenario_name = scenario
            row = 0
            for sub_set in data_dict[scenario].keys():
                print("    " + sub_set)
                col = 0
                for run_type in data_dict[scenario][sub_set].keys():
                    print("      " + run_type)
                    df = pd.DataFrame.from_dict(
                        data_dict[scenario][sub_set][run_type][key], orient='index').sort_index()
                    print(df)
                    df.plot(ax=axes[row, col], kind="bar", subplots=True)
                    axes[row, col].set_title(f"{sub_set} - {run_type}")
                    axes[row, col].get_legend().remove()
                    col += 1
                row += 1

        fig.suptitle(f"{key.replace('_', ' ').title()} {scenario_name}")
        fig.delaxes(axes[0, 2])
        fig.delaxes(axes[0, 3])
        fig.delaxes(axes[1, 2])
        fig.delaxes(axes[1, 3])

    plt.subplots_adjust(hspace=0.6, wspace=0.2, left=0.03, top=0.95, bottom=0.1, right=0.99)
    plt.show()
