from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.syscall import Syscall


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
        hidden_state = None
        cell_state = None
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    anomaly_score, hidden_state, cell_state = self._decision_engine.predict(feature_vector,
                                                                                            hidden_state,
                                                                                            cell_state)
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            hidden_state = None
            cell_state = None
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()
        self._threshold = max_score
        print(f"Calculated a threshold of {self._threshold}")

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

        hidden_state = None
        cell_state = None

        for recording in tqdm(data, description, unit=" recording"):
            if self._alarm is not False:
                self._alarm = False
            if recording.metadata()["exploit"] is True:
                exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            else:
                exploit_time = None

            for syscall in recording.syscalls():

                syscall_time = Syscall.timestamp_unix_in_ns(syscall) * (10 ** (-9))
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)

                if feature_vector is not None:
                    anomaly_score, hidden_state, cell_state = self._decision_engine.predict(feature_vector,
                                                                                            hidden_state,
                                                                                            cell_state)

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
            hidden_state = None
            cell_state = None
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()

        if tp + fn == 0:
            re = 0
        else:
            re = tp / (tp + fn)
        if tp + fp == 0:
            pr = 0
        else:
            pr = tp / (tp + fp)
        if pr + re == 0:
            f1 = 0
        else:
            f1 = 2 * ((pr * re) / (pr + re))

        self._performance_values = {"false positives": fp,
                                    "true positives": tp,
                                    "true negatives": tn,
                                    "false negatives": fn,
                                    "alarms in recording": alarm_count,
                                    "consecutive false alarms": cfa_count,
                                    "Recall": re,
                                    "Precision": pr,
                                    "F1": f1}



    def get_performance(self):

        """
        returns dict with performance values

        """

        return self._performance_values
