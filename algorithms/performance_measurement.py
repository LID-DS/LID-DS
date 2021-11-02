from dataloader.recording import Recording
from dataloader.syscall import Syscall


class PerformanceMeasurement:

    def __init__(self):
        self._threshold = 0.0
        self._performance_values = {}
        self._current_exploit_time = None
        self._exploit_count = 0
        self._alarm = False
        self._fp = 0
        self._tp = 0
        self._tn = 0
        self._fn = 0
        self._alarm_count = 0
        self._cfp_count = 0
        self._current_cfp_stream = 0
        self.result = None

    def set_threshold(self, threshold: float):
        self._threshold = threshold

    def new_recording(self, recording: Recording):
        if self._alarm is not False:
            self._alarm = False

        if recording.metadata()["exploit"] is True:

            self._current_exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            self._exploit_count += 1
        else:
            self._current_exploit_time = None

    def analyze_syscall(self, syscall: Syscall, anomaly_score: float):
        syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))

        # files with exploit
        if self._current_exploit_time is not None:
            if anomaly_score > self._threshold:
                if self._current_exploit_time > syscall_time:
                    self._fp += 1
                    self._current_cfp_stream += 1
                elif self._current_exploit_time < syscall_time:
                    if self._alarm is False:
                        self._tp += 1
                        self._alarm_count += 1
                        self._alarm = True
                    elif self._alarm is True:
                        self._tp += 1

            elif anomaly_score < self._threshold:
                if self._current_cfp_stream > 0:
                    self._current_cfp_stream = 0
                    self._cfp_count += 1
                if self._current_exploit_time > syscall_time:
                    self._tn += 1
                elif self._current_exploit_time < syscall_time:
                    self._fn += 1

        # files without exploit
        elif self._current_exploit_time is None:
            if anomaly_score > self._threshold:
                self._fp += 1
                self._current_cfp_stream += 1
            if anomaly_score < self._threshold:
                if self._current_cfp_stream > 0:
                    self._current_cfp_stream = 0
                    self._cfp_count += 1
                self._tn += 1

    def get_performance(self):

        detection_rate = self._alarm_count / self._exploit_count
        precision_cfa = self._alarm_count / (self._alarm_count + self._cfp_count)
        precision_sys = self._alarm_count / (self._alarm_count + self._fp)

        performance_values = {"false_positives": self._fp,
                              "true_positives": self._tp,
                              "true_negatives": self._tn,
                              "false_negatives": self._fn,
                              "alarm_count": self._alarm_count,
                              "exploit_count": self._exploit_count,
                              "detection_rate": detection_rate,
                              "consecutive_false_positives": self._cfp_count,
                              "recall": detection_rate,
                              "precision_with_cfa": precision_cfa,
                              "precision_with_syscalls": precision_sys
                              }
        self.result = performance_values

        return performance_values
