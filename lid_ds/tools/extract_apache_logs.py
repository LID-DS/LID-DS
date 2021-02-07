import subprocess
import sys
import csv
import gc
import argparse

import numpy as np
from datetime import datetime
import os

import pandas
import math

# to remove first line
# sed -i 1d access.log

cols_v1 = {0: 'ip', 3: 'time', 4: 'request', 5: 'status', 6: 'size'}
cols_v2 = {0: 'ip', 3: 'time', 4: 'request', 5: 'status',
           6: 'size', 7: 'referer', 8: 'user_agent'}
types_v1 = {'ip': np.str, 'time': np.float,
            'request': np.str, 'status': np.int, 'size': np.float}
types_v2 = {'ip': np.str, 'time': np.float, 'request': np.str,
            'status': np.int, 'size': np.float, 'referer': np.str, 'user_agent': np.str}


def parse_log_line(line, v1):
    end_of_request = len(line) - (2 if v1 else 5)
    result = []
    # ip, ...
    result.extend(line[:3])
    # join timestamp and remove []
    ts = " ".join(line[3:5])[1:-1]
    ts = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    result.append(ts)
    # join request
    result.append(" ".join(line[5:end_of_request]))
    # rest
    result.extend(line[end_of_request:])
    # filter out unused cols
    cols = cols_v1.keys() if v1 else cols_v2.keys()
    return [result[i] for i in cols]


def subset_to_df(subset, v1):
    cols = cols_v1.values() if v1 else cols_v2.values()
    types = types_v1 if v1 else types_v2
    df = pandas.DataFrame(subset, columns=list(cols))
    return df.astype(types, errors='ignore')


def load_log_to_hdf(log_path, hdf_path, v1=False, limit=math.inf, zeroing=False):
    print("------ Processing file: %s ------" % log_path)
    print("Removing old hdf file...")
    try:
        os.remove(hdf_path)
    except:
        pass
    print("Preprocessing file...")
    lines = []
    with open(log_path, "rb") as file:
        for line in file:
            lines.append(line.decode("utf-8", 'ignore'))

    with open(log_path, "w") as file:
        for line in lines:
            file.write(line)

    wc = int(subprocess.check_output("/usr/bin/wc -l %s" %
                                     log_path, shell=True).split()[0])
    dfs = []

    with open(log_path) as file:
        r = csv.reader(file, delimiter=' ', quotechar='"')
        count = 0
        subset = []
        for row in r:
            if count > limit:
                break
            if len(subset) > 500000:
                dfs.append(subset_to_df(subset, v1))
                subset = []
            try:
                subset.append(parse_log_line(row, v1))
            except:
                pass
            if count % 100000 == 0:
                sys.stdout.write("\rParsing file (%d%%)" %
                                 (count / wc * 100))
                sys.stdout.flush()
            count += 1

        dfs.append(subset_to_df(subset, v1))

    print("\nConcatenating Dataframes...")
    df: pandas.DataFrame = pandas.concat(dfs, ignore_index=True, copy=False)
    print("Free some memory...")
    del dfs
    del subset
    gc.collect()
    print("Combining IPs...")
    # combine_ips_within_time(df)
    combine_following_ips(df)

    if zeroing:
        print("Zeroing time...")
        df['time'] -= df['time'].min()

    print("\nWriting HDF...")
    df.to_hdf(hdf_path, 'data')


def combine_ips_within_time(data: pandas.DataFrame):
    last_ips = []
    lines_to_remove = []
    for index, [ip, time] in data[["ip", "time"]].iterrows():
        # Remove all with with same ip within 2 seconds
        last_ips = [x for x in last_ips if time - x[1] < 1]

        if ip in (_ip for _ip, _time in last_ips):
            lines_to_remove.append(index)
        last_ips.append((ip, time))

    print("Dropping now")
    data.drop(lines_to_remove, inplace=True)


def combine_following_ips(data: pandas.DataFrame):
    last_ip = ""
    lines_to_remove = []
    for index, ip in data["ip"].iteritems():
        if ip == last_ip:
            lines_to_remove.append(index)
        else:
            last_ip = ip
    data.drop(lines_to_remove, inplace=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("hdf")
    parser.add_argument(
        "--limit", help="limit the lines to read", type=int, default=math.inf)
    parser.add_argument("--v1", help="use apache v1 logs", action='store_true')
    parser.add_argument(
        "--zeroing", help="zeroing the timestamps", action='store_true')

    args = parser.parse_args()

    load_log_to_hdf(args.log, args.hdf,
                    v1=args.v1, limit=args.limit, zeroing=args.zeroing)
