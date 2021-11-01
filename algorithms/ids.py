from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_preprocessor import DataPreprocessor


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
        self._first_syscall_after_exploit_list = []
        self._last_syscall_of_recording_list = []

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
            detects: false positives, true positives:alarms, true negatives, false negatives, consecutive false alarms,
                     detection rate based on anomaly scores and metadata
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

        # syscall index and exploit count needed for plotting
        syscall_count_for_plot_exploit_recordings = 1
        exploit_count = 0

        for recording in tqdm(data, description, unit=" recording"):
            if self._alarm is not False:
                self._alarm = False

            if recording.metadata()["exploit"] is True:
                exploit_exists = True
                exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
                exploit_count += 1
            else:
                exploit_exists = False
                exploit_time = None

            first_sys_after_exploit = False

            for syscall in recording.syscalls():
                syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)

                # getting index of first syscall after exploit of each recording for plotting
                if exploit_exists is True and syscall_time >= exploit_time and first_sys_after_exploit is False:
                    self._first_syscall_after_exploit_list.append(syscall_count_for_plot_exploit_recordings)
                    first_sys_after_exploit = True

                if exploit_time is not None:
                    syscall_count_for_plot_exploit_recordings += 1

                if feature_vector is not None:
                    anomaly_score = self._decision_engine.predict(feature_vector)

                    # saving scores separately for plotting
                    if exploit_time is not None:
                        self._anomaly_scores_exploits.append(anomaly_score)
                    if exploit_time is None:
                        self._anomaly_scores_no_exploits.append(anomaly_score)

                    # files with exploit
                    if exploit_time is not None:
                        if anomaly_score > self._threshold:
                            if exploit_time > syscall_time:
                                fp += 1
                                cfa_stream += 1
                            elif exploit_time < syscall_time:
                                if self._alarm is False:
                                    tp += 1
                                    alarm_count += 1
                                    self._alarm = True
                                elif self._alarm is True:
                                    tp += 1

                        elif anomaly_score < self._threshold:
                            if cfa_stream > 0:
                                cfa_stream = 0
                                cfa_count += 1
                            if exploit_time > syscall_time:
                                tn += 1
                            elif exploit_time < syscall_time:
                                fn += 1

                    # files without exploit
                    elif exploit_time is None:
                        if anomaly_score > self._threshold:
                            fp += 1
                            cfa_stream += 1
                        if anomaly_score < self._threshold:
                            if cfa_stream > 0:
                                cfa_stream = 0
                                cfa_count += 1
                            tn += 1

            # getting index of last syscall of each recording for plotting
            if exploit_time is not None:
                self._last_syscall_of_recording_list.append(syscall_count_for_plot_exploit_recordings)

            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()

        try:
            re = alarm_count / exploit_count
        except ZeroDivisionError:
            print("Division by Zero not possible, no exploits counted.")

        self._performance_values = {"false positives": fp,
                                    "true positives": tp,
                                    "true negatives": tn,
                                    "false negatives": fn,
                                    "recording with detected alarm count/true positives on file level": alarm_count,
                                    "exploit count": exploit_count,
                                    "false negatives on file level": exploit_count - alarm_count,
                                    "detection rate": alarm_count / exploit_count,
                                    "consecutive false alarms": cfa_count,
                                    "recall file level": re,
                                    }

    def get_performance(self):

        """
        returns dict with performance values
        """

        return self._performance_values

    def get_plotting_data(self):

        """
           returns relevant information for plot
        """

        return self._threshold, self._first_syscall_after_exploit_list, self._last_syscall_of_recording_list, self._anomaly_scores_exploits, self._anomaly_scores_no_exploits