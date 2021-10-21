from typing import Union, Type, Generator

from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.syscall import Syscall

import matplotlib.pyplot as plt
plt.rcParams.update({'font.size': 26})


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 data_preprocessor: DataPreprocessor,
                 decision_engine: BaseDecisionEngine):
        self._data_loader = data_loader
        self._data_preprocessor = data_preprocessor
        self._decision_engine = decision_engine
        self._threshold = 0.0
        self._performance_values = {}
        self._alarm = False

        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._syscalls_near_exploit = []
        self._new_rec_marker = []

    def train_decision_engine(self):
        # train of DE
        data = self._data_loader.training_data()
        description = 'Training: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    self._decision_engine.train_on(feature_vector)
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()
        self._decision_engine.fit()

    def determine_threshold(self):
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    anomaly_score = self._decision_engine.predict(feature_vector)
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()
        self._threshold = max_score

    def do_detection(self):
        """
            detects: false positives, true positives, true negatives, false negatives, consecutive false alarms
                         from feature_vectors and metadata

            returns: counts of fp, tp, tn, fn, cfa as int, alarms per rec

        """
        fp = 0
        tp = 0
        tn = 0
        fn = 0
        cfa_stream = 0
        alarm_count = 0
        cfa_count = 0

        data = self._data_loader.test_data()
        description = 'anomaly detection: '

        syscall_count_for_plot = 1


        for recording in tqdm(data, description, unit=" recording"):
            if self._alarm is not False:
                self._alarm = False
            if recording.metadata()["exploit"] is True:
                exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            else:
                exploit_time = None

            new_recording = True
            first_sys_after_exploit = False

            for syscall in recording.syscalls():

                syscall_time = Syscall.timestamp_unix_in_ns(syscall) * (10 ** (-9))
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)

                if new_recording is True:
                    self._new_rec_marker.append(syscall_count_for_plot)
                    new_recording = False

                if exploit_time is not None and syscall_time > exploit_time and first_sys_after_exploit is False:
                    self._syscalls_near_exploit.append(syscall_count_for_plot)

                    first_sys_after_exploit = True

                if feature_vector is not None:
                    syscall_count_for_plot += 1
                    anomaly_score = self._decision_engine.predict(feature_vector)
                    if exploit_time is not None:
                        self._anomaly_scores_exploits.append(anomaly_score)

                    if exploit_time is None:
                        self._anomaly_scores_no_exploits.append(anomaly_score)

                    if anomaly_score > self._threshold:
                        if exploit_time is not None:
                            if exploit_time > syscall_time:
                                fp += 1
                                cfa_stream += 1
                            elif exploit_time < syscall_time and self._alarm is False:
                                tp += 1
                                alarm_count += 1
                                self._alarm = True
                            elif exploit_time < syscall_time and self._alarm is True:
                                tp += 1
                        else:
                            fp += 1

                    if anomaly_score < self._threshold:
                        if exploit_time is not None:
                            if cfa_stream > 0:
                                cfa_stream = 0
                                cfa_count += 1

                            if exploit_time > syscall_time:
                                tn += 1
                            elif exploit_time < syscall_time:
                                fn += 1
                            else:
                                tn += 1

            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()

        re = tp / (tp + fn)
        pr = tp / (tp + fp)

        self._performance_values = {"false positives": fp,
                                    "true positives": tp,
                                    "true negatives": tn,
                                    "false negatives": fn,
                                    "alarms in recording": alarm_count,
                                    "consecutive false alarms": cfa_count,
                                    "Recall": re,
                                    "Precision": pr,
                                    "F1": 2 * ((pr * re) / (pr + re))}

    def get_performance(self):

        """
        returns dict with performance values

        """

        return self._performance_values

    def plot_performance(self):

        """
            creates 2 plots: normal activity and exploit cases
        """

        fig = plt.figure()
        ax = fig.add_subplot(111)  # The big subplot
        ax1 = fig.add_subplot(211)
        ax2 = fig.add_subplot(212)


        ax.spines['top'].set_color('none')
        ax.spines['bottom'].set_color('none')
        ax.spines['left'].set_color('none')
        ax.spines['right'].set_color('none')
        ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

        #first subplot for normal activity
        ax1.plot(self._anomaly_scores_no_exploits)
        ax1.axhline(y=self._threshold, color="g")

        #second subplot for exploits
        done = False
        start = 0
        end = len(self._anomaly_scores_exploits)
        while not done:
            quadrat1 = self._syscalls_near_exploit[start]
            quadrat2 = next(x for x in self._new_rec_marker if x > quadrat1)
            ax2.axvspan(quadrat1, quadrat2, color="red", alpha=0.4)
            start +=1
        ax2.plot(self._anomaly_scores_exploits)
        ax2.axhline(y=self._threshold, color="g")

        # Set common labels
        ax.set_ylabel('anomaly scores')

        ax1.set_title('normal activity')
        ax2.set_title('exploitative activity')

        """fig = plt.figure()
        fig.suptitle("Anomaly scores for normal and abnormal cases")
        ax1 = fig.add_subplot(111)
        ax1.plot(self._anomaly_scores_exploits)
        ax1.title.set_text("with exploits")
        ax2 = fig.add_subplot(212)
        ax2.plot(self._anomaly_scores_no_exploits)
        ax2.axhline(y=self._threshold, color="g")
        ax2.title.set_text("normal activity")"""

        """fig,(ax1, ax2) = plt.subplots(2, sharey=True)
        ax1.plot(self._anomaly_scores_exploits)
        ax1.set(title="anomaly scores exploits")
        ax2.plot(self._anomaly_scores_no_exploits)
        ax2.plot(title="anomaly scores normal activity")
        ax1.axhline(y=self._threshold, color="g")
        ax2.axhline(y=self._threshold, color="g")"""


        """plt.plot(self._anomaly_scores_exploits)
        plt.axhline(y=self._threshold, color="g")
        for syscall in self._syscalls_near_exploit:
            plt.axvline(x=syscall, color="r")

        for marker in self._new_rec_marker:
            plt.axvline(x=marker, color="y")"""



        plt.show()

        return 0
