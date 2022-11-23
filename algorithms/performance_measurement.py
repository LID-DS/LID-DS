from __future__ import annotations

from dataloader.syscall import Syscall
from dataloader.base_recording import BaseRecording

from algorithms.alarms import Alarms


class Performance:

    def __init__(self, create_alarms: bool = False):
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
        self._current_cfp_stream = 0
        self.result = None
        self.create_alarms = create_alarms

        # for cfp screening
        self._cfp_count_exploits = 0
        self._current_cfp_stream_exploits = 0
        self._exploit_anomaly_score_count = 0
        self._first_syscall_of_cfp_list_exploits = []
        self._last_syscall_of_cfp_list_exploits = []
        self._cfp_counter_wait_exploits = False

        self._cfp_count_normal = 0
        self._current_cfp_stream_normal = 0
        self._normal_score_count = 0
        self._first_syscall_of_cfp_list_normal = []
        self._last_syscall_of_cfp_list_normal = []
        self._cfp_counter_wait_normal = False
        if self.create_alarms:
            self.alarms = Alarms()
        else:
            self.alarms = None

    def set_threshold(self, threshold: float):
        self._threshold = threshold

    def set_exploit_time(self, exploit_time):
        self._current_exploit_time = exploit_time

    def analyze_syscall(self, syscall: Syscall, anomaly_score: float):
        """
        counts performance values with syscall and anomaly score as input,
        differentiates between normal and exploit files
        """

        syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))

        # files with exploit
        if self._current_exploit_time is not None:
            self._exploit_anomaly_score_count += 1
            if anomaly_score > self._threshold:
                if self._current_exploit_time > syscall_time:
                    self._fp += 1
                    self._current_cfp_stream_exploits += 1
                    self._cfp_start_exploits()
                    if self.create_alarms:
                        self.alarms.add_or_update_alarm(syscall, False)
                elif self._current_exploit_time <= syscall_time:
                    self._cfp_end_exploits()
                    if self.create_alarms:
                        self.alarms.add_or_update_alarm(syscall, True)
                    if self._alarm is False:
                        self._tp += 1
                        self._alarm_count += 1
                        self._alarm = True
                    elif self._alarm is True:
                        self._tp += 1

            elif anomaly_score <= self._threshold:
                if self.create_alarms:
                    self.alarms.end_alarm()
                self._cfp_end_exploits()
                if self._current_exploit_time > syscall_time:
                    self._tn += 1
                elif self._current_exploit_time <= syscall_time:
                    self._fn += 1

        # files without exploit
        elif self._current_exploit_time is None:
            self._normal_score_count += 1
            if anomaly_score > self._threshold:
                self._fp += 1
                self._current_cfp_stream_normal += 1
                self._cfp_start_normal()
                if self.create_alarms:
                    self.alarms.add_or_update_alarm(syscall, False)
            if anomaly_score <= self._threshold:
                if self.create_alarms:
                    self.alarms.end_alarm()
                self._cfp_end_normal()
                self._tn += 1

    def add(left: Performance, right: Performance) -> Performance:
        final_performance = Performance()
        final_performance.set_threshold(left._threshold)
        final_performance._alarm_count = left._alarm_count + right._alarm_count
        final_performance._exploit_count = left._exploit_count + right._exploit_count
        final_performance._fp = left._fp + right._fp
        final_performance._tp = left._tp + right._tp
        final_performance._fn = left._fn + right._fn
        final_performance._tn = left._tn + right._tn
        final_performance._cfp_count_exploits = left._cfp_count_exploits + right._cfp_count_exploits
        final_performance._cfp_count_normal = left._cfp_count_normal + right._cfp_count_normal
        return final_performance

    def add_with_alarms(left: Performance, right: Performance) -> Performance:
        final_performance = Performance.add(left, right)
        final_performance.alarms = Alarms()
        final_performance.alarms.alarm_list = left.alarms.alarm_list + right.alarms.alarm_list
        return final_performance

    def new_recording(self, recording: BaseRecording):
        """
        at beginning of each recording: saves exploit time, resets flags and counts

        """
        # making sure there is only one true detected alarm in each exploit recording
        if self._alarm is not False:
            self._alarm = False

        if recording.metadata()["exploit"] is True:

            # TODO: fix the timestamps
            self._current_exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            self._exploit_count += 1
        else:
            self._current_exploit_time = None

        # ending cfa before new recording starts
        self._cfp_end_exploits()
        self._cfp_end_normal()

        # ending alarm
        if self.create_alarms:
            self.alarms.end_alarm()

    def __repr__(self) -> str:
        return f"Performance-Instance: Alarm_Count: {self._alarm_count}, Exploit_count: {self._exploit_count}, FPs: {self._fp}, TPs: {self._tp}, FNs: {self._fn}, TNs: {self._tn}"

    def _cfp_start_exploits(self):
        """
        appends respective lists with cfa indices (exploit cases),
        sets flags for correct index counting

        """
        if self._cfp_counter_wait_exploits is False:
            self._first_syscall_of_cfp_list_exploits.append(self._exploit_anomaly_score_count)
            self._cfp_counter_wait_exploits = True

    def _cfp_end_exploits(self):
        """
        appends respective lists with cfa indices (exploit cases),
        sets flags for correct index counting

        """
        if self._cfp_counter_wait_exploits is True:
            if self._current_cfp_stream_exploits > 0:
                self._current_cfp_stream_exploits = 0
                self._cfp_count_exploits += 1
                self._last_syscall_of_cfp_list_exploits.append(self._exploit_anomaly_score_count)
                self._cfp_counter_wait_exploits = False

    def _cfp_start_normal(self):
        """
        appends respective lists with cfa indices (normal cases),
        sets flags for correct index counting

        """
        if self._cfp_counter_wait_normal is False:
            self._first_syscall_of_cfp_list_normal.append(self._normal_score_count)
            self._cfp_counter_wait_normal = True

    def _cfp_end_normal(self):
        """
        appends respective lists with cfa indices (normal cases),
        sets flags for correct index counting

        """
        if self._cfp_counter_wait_normal is True:
            if self._current_cfp_stream_normal > 0:
                self._current_cfp_stream_normal = 0
                self._cfp_count_normal += 1
                self._last_syscall_of_cfp_list_normal.append(self._normal_score_count)
                self._cfp_counter_wait_normal = False

    def get_cfp_indices(self):
        """
        returns cfp syscall indices in lists for plotting

        """
        return self._first_syscall_of_cfp_list_exploits, self._last_syscall_of_cfp_list_exploits, self._first_syscall_of_cfp_list_normal, self._last_syscall_of_cfp_list_normal

    def get_results(self):
        try:
            detection_rate = self._alarm_count / self._exploit_count
        except ZeroDivisionError:
            detection_rate = 0
        try:
            precision_cfa = self._alarm_count / (self._alarm_count + self._cfp_count_normal + self._cfp_count_exploits)
        except ZeroDivisionError:
            precision_cfa = 0
        try:
            precision_sys = self._alarm_count / (self._alarm_count + self._fp)
        except ZeroDivisionError:
            precision_sys = 0

        try:
            f1_cfa = 2 * (precision_cfa * detection_rate) / (precision_cfa + detection_rate)
        except ZeroDivisionError:
            f1_cfa = 0

        performance_values = {"false_positives": self._fp,
                              "true_positives": self._tp,
                              "true_negatives": self._tn,
                              "false_negatives": self._fn,
                              "correct_alarm_count": self._alarm_count,
                              "exploit_count": self._exploit_count,
                              "detection_rate": detection_rate,
                              "consecutive_false_positives_normal": self._cfp_count_normal,
                              "consecutive_false_positives_exploits": self._cfp_count_exploits,
                              "recall": detection_rate,
                              "precision_with_cfa": precision_cfa,
                              "precision_with_syscalls": precision_sys,
                              "f1_cfa": f1_cfa,
                              "threshold": self._threshold
                              }
        self.result = performance_values

        return performance_values
