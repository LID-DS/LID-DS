import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def duration_vis(syscalls):
    plt.figure(figsize=(12,9))
    ax = plt.subplot(111)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    plt.xlabel("System Call", fontsize=16)
    plt.ylabel("Duration", fontsize=16)
    types = set([o.type for o in syscalls])
    counts = []
    for type_label in types:
        counts.append(sum([1 for syscall in syscalls if syscall.type == type_label]))
    data = zip(types,counts)
    data_sorted = sorted(data, key=lambda x: x[1], reverse=True)
    labels, ys = zip(*data_sorted[0:10])
    width = 1
    xs = np.arange(len(labels))
    ax.bar(xs, ys, width, align='center')
    ax.set_xticks(xs)
    ax.set_xticklabels(labels)
    ax.set_yticks(ys)
    plt.text(1300, -5000, 'Data source of {} system calls'.format(len(syscalls)), fontsize=10)
    plt.show()

