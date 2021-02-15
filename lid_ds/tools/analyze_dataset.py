import argparse
import pandas as pd
import numpy as np

from lid_ds.sim.sampler import Sampler


def load(dataset):
    df = pd.read_hdf(dataset)
    df['time'] = pd.to_datetime(df['time'], unit='s')
    df.sort_values(by=['time'], inplace=True)
    return df


def absolute(df):
    result = {}

    result["IPs"] = df["ip"].unique().size
    result["gesamt"] = df.size
    result["pro Tag"] = df.resample("D", on="time").count()["ip"].mean()
    result["pro Stunde"] = df.resample("H", on="time").count()["ip"].mean()
    result["pro Minute"] = df.resample("T", on="time").count()["ip"].mean()
    result["pro Sekunde"] = df.resample("S", on="time").count()["ip"].mean()

    return pd.DataFrame.from_dict(result, orient="index")


def ip_based(df):
    result = {}

    req_per_ip = df.groupby("ip").count()["time"]

    result["Durchschnitt"] = req_per_ip.mean()
    result["Minimum"] = req_per_ip.min()
    result["Maximum"] = req_per_ip.max()

    for x in [1, 5, 10, 50, 100, 1000]:
        num = req_per_ip[req_per_ip > x].size
        percent = round(num / req_per_ip.size * 100, 2)
        result[f"{x} Anfragen"] = f"{num} ({percent}%)"

    return pd.DataFrame.from_dict(result, orient="index")


def time_based(df):
    result = {}

    diff = df["time"].diff().dropna()

    result["Durschnitt"] = pretty_format_timedelta(diff.mean())
    result["Minimum"] = pretty_format_timedelta(diff.min())
    result["Maximum"] = pretty_format_timedelta(diff.max())

    times = df.groupby("ip")["time"].diff().dropna()
    size = times.size
    for x in [10, 60, 300, 600, 3600]:
        matching = times[times <= pd.Timedelta(x, "sec")].size
        result[f"{x}s"] = f"{matching} ({round(matching / size * 100, 2)}%)"

    return pd.DataFrame.from_dict(result, orient="index")


def pretty_format_timedelta(td):
    secs = round(td.total_seconds(), 3)

    if secs > 3600:
        h, m = divmod(secs, 3600)
        m, s = divmod(m, 60)
        return f"{h}h {m}min {s}s"
    elif secs > 60:
        m, s = divmod(secs, 60)
        return f"{m}min {s}s"
    else:
        return f"{secs}s"


def create_sampler(dataset):
    df = pd.read_hdf(dataset)
    return Sampler(df)


def analyze_dataset(dataset, runs=10, user=20, length=300, entries_lower=15, entries_upper=50):
    sampler = create_sampler(dataset)

    functions = [
        ("RS", sampler.random_sampling, [user, length, entries_lower, entries_upper]),
        ("TS", sampler.timerange_sampling, [user, length]),
        ("IS", sampler.ip_sampling, [user, length]),
        ("ITS", sampler.ip_timerange_sampling, [user, length]),
        ("ES", sampler.extraction_sampling, [length]),
    ]

    results = {}

    for name, func, args in functions:
        results[name] = analyze_sampling_method(runs, func, args)

    return pd.DataFrame.from_dict(results, orient="index")


def analyze_sampling_method(runs, sampler_func, args):
    data = pd.DataFrame(columns=["user", "wts"])
    helper = {}
    results = {}

    for _ in range(runs):
        wts = pd.DataFrame(sampler_func(*args))
        data = data.append({'user': len(wts), 'wts': wts}, ignore_index=True)

    helper['mean_actions'] = []
    helper['mean_wait_time'] = []
    helper['empty_wait_times'] = 0

    for run in data['wts']:
        helper['mean_wait_time'].append(
            run.dropna().mean(axis=1).fillna(0).mean())

        for index, row in run.iterrows():
            if row.isna().all():
                helper['empty_wait_times'] += 1
            helper['mean_actions'].append(len(row.dropna()))

    results['mean_user'] = data['user'].mean()
    results['mean_actions'] = np.mean(helper['mean_actions'])
    results['mean_wait_time'] = np.mean(helper['mean_wait_time'])
    results['empty_wait_times'] = f"{int(helper['empty_wait_times'] / data['user'].sum() * 100)}%"

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("hdf")
    parser.add_argument("--absolute", help="calculate absolute metrics", action='store_true')
    parser.add_argument("--ip", help="calculate ip metrics", action='store_true')
    parser.add_argument("--time", help="calculate time metrics", action='store_true')
    parser.add_argument("--sampling", help="calculate the sampling metrics", type=int, nargs=5, metavar=('runs', 'user', 'length', 'entries_lower', 'entries_upper'), default=None)

    args = parser.parse_args()

    df_metrics = load(args.hdf)

    if args.absolute:
        print(absolute(df_metrics))

    if args.ip:
        print(ip_based(df_metrics))

    if args.time:
        print(time_based(df_metrics))

    if args.sampling:
        print(analyze_dataset(args.hdf, *args.sampling))


