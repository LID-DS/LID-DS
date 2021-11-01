from dataloader.recording import Recording
from dataloader.syscall import Syscall

class PerformanceMeasurement:

    def __init__(self, threshold:int):
        self._threshold = threshold
        self._performance_values = {}
        self._alarm = False
        self._exploit_time = None
        self._exploit_exists = False
        self._first_sys_after_exploit = None
        self._syscall_count_for_plot_exploit_recordings = None

    def scan_recording(self, recording: Recording):
        self._syscall_count_for_plot_exploit_recordings = 1
        exploit_count = 0
        if self._alarm is not False:
            self._alarm = False

        if recording.metadata()["exploit"] is True:
            self._exploit_exists = True
            self._exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            exploit_count += 1
        else:
            self._exploit_exists = False
            self._exploit_time = None

        self._first_sys_after_exploit = False

    def scan_syscall(self, syscall: Syscall):

        fp = 0
        tp = 0
        tn = 0
        fn = 0
        cfa_stream = 0
        alarm_count = 0
        cfa_count = 0

        syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))
        feature_vector = self._data_preprocessor.syscall_to_feature(syscall)

        if feature_vector is not None:
            anomaly_score = self._decision_engine.predict(feature_vector)

            # getting index of first syscall after exploit of each recording (for plotting)
            if self._exploit_exists is True and self._exploit_time is not None:
                if syscall_time >= self._exploit_time and self._first_sys_after_exploit is False:
                    self._first_syscall_after_exploit_list.append(self._syscall_count_for_plot_exploit_recordings)
                    self._first_sys_after_exploit = True
                self._syscall_count_for_plot_exploit_recordings += 1

            # saving scores separately for plotting
            if self._exploit_time is not None:
                self._anomaly_scores_exploits.append(anomaly_score)
            if self._exploit_time is None:
                self._anomaly_scores_no_exploits.append(anomaly_score)

                # files with exploit
                if self._exploit_time is not None:
                    if anomaly_score > self.threshold:
                        if self._exploit_time > syscall_time:
                            fp += 1
                            cfa_stream += 1
                        elif self._exploit_time < syscall_time:
                            if self._alarm is False:
                                tp += 1
                                alarm_count += 1
                                self._alarm = True
                            elif self._alarm is True:
                                tp += 1

                    elif anomaly_score < self.threshold:
                        if cfa_stream > 0:
                            cfa_stream = 0
                            cfa_count += 1
                        if self._exploit_time > syscall_time:
                            tn += 1
                        elif self._exploit_time < syscall_time:
                            fn += 1

                # files without exploit
                elif self._exploit_time is None:
                    if anomaly_score > self.threshold:
                        fp += 1
                        cfa_stream += 1
                    if anomaly_score < self.threshold:
                        if cfa_stream > 0:
                            cfa_stream = 0
                            cfa_count += 1
                        tn += 1



        try:
            re = alarm_count / self._exploit_count
        except ZeroDivisionError:
            print("Division by Zero not possible, no exploits counted.")

        self._performance_values = {"false positives": fp,
                                        "true positives": tp,
                                        "true negatives": tn,
                                        "false negatives": fn,
                                        "recording with detected alarm count/true positives on file level": alarm_count,
                                        "exploit count": self._exploit_count,
                                        "false negatives on file level": self._exploit_count - alarm_count,
                                        "detection rate": alarm_count / self._exploit_count,
                                        "consecutive false alarms": cfa_count,
                                        "recall file level": re}

    def print_performance(self):

        """
        returns dict with performance values
        
        """
        print(self._performance_values)

    def get_plotting_data(self):

            ????????????????????????
            # getting index of last syscall of each recording for plotting
            if self._exploit_time is not None:
                self._last_syscall_of_recording_list.append(self._syscall_count_for_plot_exploit_recordings)


