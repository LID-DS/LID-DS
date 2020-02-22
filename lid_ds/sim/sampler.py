import numpy as np
import pandas as pd
import os, random
import matplotlib.pyplot as plt

this_dir = os.path.dirname(os.path.realpath(__file__))
print("reading raith")
data_raith: pd.DataFrame = None#pd.read_hdf(os.path.join(this_dir, "raith.h5"))
print("reading nasa")
data_nasa: pd.DataFrame = None#pd.read_hdf(os.path.join(this_dir, "nasa.h5"))
fig = plt.figure(figsize=(5, 15))


def generate_sample_real_data(secs):
    sample = data_nasa["time"]
    first_time = random.randrange(sample.min(), sample.max())
    sample = sample[sample.isin(range(first_time, first_time + secs))]
    sample -= first_time
    return sample.to_numpy(np.float64)


def generate_sample(secs, choice_factor=0.5, random_range=0.1):
    # random difference between behaviors +-range
    variation = round(random.uniform(1 - random_range, 1 + random_range), 2)
    sample = np.random.choice(data_raith['time'], int(secs * choice_factor * variation))
    # scale sample to secs
    return np.round((sample / np.amax(sample) * secs), 0)


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