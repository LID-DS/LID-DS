import numpy as np
import pandas as pd
import os


def convert_to_wait_times(series, to_array=False):
    wt = series.sort_values().diff()[1:-1]
    if to_array:
        return wt.tolist()
    else:
        return wt


class Sampler:
    def __init__(self, dataset):
        if isinstance(dataset, str):
            dir_path = os.path.dirname(os.path.realpath(__file__))
            hdf_path = os.path.join(dir_path, f"datasets/{dataset}.h5")
            if not os.path.exists(hdf_path):
                raise Exception("Dataset not found")
            self.df: pd.DataFrame = pd.read_hdf(hdf_path)
        elif isinstance(dataset, pd.DataFrame):
            self.df = dataset
        else:
            raise Exception("Invalid dataset supplied")
        self.random = np.random.default_rng()

    def random_sampling(self, user, length, lower, upper):
        wts = []
        for _ in range(user):
            # random count, add two for upper and lower limit
            entry_count = self.random.integers(lower, upper) + 2

            # select random
            sample = self.df.sample(entry_count)
            sample = sample["time"]

            # scale to length
            sample = sample - sample.min()
            sample = sample / sample.max() * length

            wts.append(convert_to_wait_times(sample, True))
        return wts

    def timerange_sampling(self, user, length):
        wts = []
        for _ in range(user):
            sample = self.df["time"]

            begin = np.random.choice(sample.to_numpy())

            sample = sample[sample.between(begin, begin + length)]

            wts.append(convert_to_wait_times(sample, True))
        return wts

    def ip_sampling(self, user, length):
        wts = []
        for _ in range(user):
            ip = np.random.choice(self.df["ip"])

            sample = self.df[self.df['ip'] == ip]

            sample = sample['time']

            sample = sample - sample.min()
            sample = sample / sample.max() * length

            wts.append(convert_to_wait_times(sample, True))

        return wts

    def ip_timerange_sampling(self, user, length, min_actions=1):
        wts = []
        for _ in range(user):
            while True:
                entry = self.df.sample(1).iloc[0]

                sample = self.df[self.df['ip'] == entry['ip']]

                sample = sample['time']
                sample = sample[sample.between(
                    entry['time'], entry['time'] + length)]

                wait_times = convert_to_wait_times(sample, True)
                if len(wait_times) >= min_actions:
                    wts.append(wait_times)
                    break

        return wts

    def extraction_sampling(self, length):
        sample = self.df["time"]
        begin = np.random.choice(sample.to_numpy())
        sample = self.df[sample.between(begin, begin + length)]

        wts = []
        for name, group in sample.groupby("ip"):
            wts.append(convert_to_wait_times(group["time"], True))
        return wts
