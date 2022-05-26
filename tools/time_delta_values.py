from dataloader.syscall import Direction
from dataloader.recording_2019 import RecordingDataParts
from dataloader.dataloader_factory import dataloader_factory
from dataloader.syscall import Syscall
from datetime import datetime

from tqdm import tqdm

import plotly.graph_objects as go
import pandas as pd


def calc_time_deltas(recording_list, max_delta, description):
    results = {
        'normal': [],
        'exploit': []
    }
    last_time = {}
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        if recording.recording_data_list[RecordingDataParts.IS_EXECUTING_EXPLOIT] == 'True':
            rec = 'exploit'
        else:
            rec = 'normal'
        for syscall in recording.syscalls():
            current_time = syscall.timestamp_datetime()
            delta, last_time = _calc_delta(current_time, syscall, last_time)
            if delta/max_delta >= 1:
                print(delta)
            results[rec].append(delta/max_delta)
        last_time = {}
    return results


def _calc_delta(current_time: datetime, syscall: Syscall, last_time) -> float:
    """
    calculates the delta to the last systall within the same thread
    (if thread aware)
    or to the last seen syscall over all
    """
    thread_id = syscall.thread_id()
    if thread_id in last_time:
        delta = current_time - last_time[thread_id]
        delta = delta.microseconds
        last_time[thread_id] = current_time
    else:
        delta = 0
        last_time[thread_id] = current_time
    return delta, last_time


def calc_max_delta(recording_list, description):
    max_delta = 0
    last_time = {}
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            current_time = syscall.timestamp_datetime()
            delta, last_time = _calc_delta(current_time, syscall, last_time)
            if delta > max_delta:
                print(delta)
                max_delta = delta
        last_time = {}
    return max_delta


if __name__ == '__main__':
    SCENARIO_NAMES = [
        # "Bruteforce_CWE-307",
        # "CVE-2012-2122",
        # "CVE-2014-0160"
        # "CVE-2017-7529",
        # "CVE-2018-3760",
        "CVE-2019-5418",
        # "PHP_CWE-434",
        # "EPS_CWE-434",
        # "ZipSlip"
    ]
    for scenario in SCENARIO_NAMES:
        # scenario = 'CVE-2017-7529'
        dataloader = dataloader_factory(f'../../Dataset/{scenario}/',
                                        Direction.CLOSE)
        result_dict = {}

        # dict to describe dataset structure
        data_parts = {
            'Training': dataloader.training_data(),
            # 'Validation': dataloader.validation_data(),
            'Test': dataloader.test_data()
        }
        delta_dict = {}
        max_delta = 0
        for data_part in data_parts.keys():
            if data_part == 'Training':
                max_delta = calc_max_delta(data_parts[data_part],
                                           f"{scenario}: {data_part}".rjust(45))
            else:
                results = calc_time_deltas(data_parts[data_part], max_delta,
                                           f"{scenario}: {data_part}".rjust(45))
                delta_dict = results

        df_normal = pd.DataFrame(delta_dict['normal'])
        # df_normal = (df_normal)/len(df_normal)
        df_exploit = pd.DataFrame(delta_dict['exploit'])
        # df_exploit = (df_exploit)/len(df_exploit)
        # df_exploit = (df_exploit-df_exploit.mean())/df_exploit.std()
        his_norm = go.Histogram(
            x=df_normal[0],
            name='nur Normalverhalten',
            marker_color='#076678',
            histnorm='percent',
            opacity=0.6,
        )
        his_exp = go.Histogram(
            x=df_exploit[0],
            name='auch Angriffsverhalten',
            marker_color='#9d0006',
            histnorm='percent',
        )
        fig = go.Figure()
        fig.add_trace(his_norm)
        fig.add_trace(his_exp)
        fig.update_layout(
            # title=f'Histogram für System Calls {title}<br> Testdaten - CVE-2017-7529',
            plot_bgcolor='#bfbfbf',
            font_color='#000000',
            xaxis=go.XAxis(
                title='Wert für tau',
                range=[0, 1.1]
            ),
            yaxis=go.YAxis(
                title='Vorkommen',
            ),
            legend=dict(
                yanchor="top",
                y=0.99,
                xanchor="right",
                x=0.99,
            ),
            yaxis_type="log",
        )
        fig.show()
        # fig.write_image(
        # f'/home/tk/Documents/Uni/Theorie/Citsci.project.report/images/CVE-2012--Test-data-time_delta.pdf')
