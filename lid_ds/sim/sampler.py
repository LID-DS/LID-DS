import numpy as np
import pandas as pd
import os, random
import matplotlib.pyplot as plt

print("Reading joined...")
this_dir = os.path.dirname(os.path.realpath(__file__))
data: pd.DataFrame = pd.read_hdf(os.path.join(this_dir, "access.h5"), "access")
fig = plt.figure(figsize=(5, 15))


def scale_sample_to(secs, sample: np.ndarray):
    return np.round((sample / np.amax(sample) * secs), 0)


def generate_sample(secs, choice_factor=0.5, random_range=0.1):
    # data = data[data['time'] > 1.46e9]
    data['time'] -= data['time'].min()
    # random difference between behaviors +-range
    variation = round(random.uniform(1 - random_range, 1 + random_range), 2)
    sample = np.random.choice(data['time'], int(secs * choice_factor * variation))
    return scale_sample_to(secs, sample)


def convert_sample_to_wait_times(sample: np.ndarray):
    sample.sort()
    wait_times = []
    last = 0
    for time in sample:
        wait_times.append(time - last)
        last = time
    return wait_times


def visualize_sample(sample: np.ndarray, bins=100):
    n = len(fig.axes)
    for i in range(n):
        fig.axes[i].change_geometry(n + 1, 1, i + 1)

    ax = fig.add_subplot(n + 1, 1, n + 1)
    ax.hist(sample, bins=bins)


def visualize(name):
    fig.savefig("behavior_%s.png" % name)
