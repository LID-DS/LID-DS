from algorithms.alarm import Alarm
from dataloader.syscall import Syscall


class Alarms:
    def __init__(self):
        """
            Manages Alarms for IDS Run
        """
        self.alarm_list = []
        self.current_alarm = None
        self._alarm_dict = None

    def add_or_update_alarm(self, syscall: Syscall, correct):
        """
            creates new alarm if no consecutive alarm row is active
            if alarm is consecutive end line and end timestamp are adjusted

            starts new consecutive row if detection correctness changes
        """
        if self.current_alarm is None:
            self.current_alarm = Alarm(syscall, correct)
            self.current_alarm.last_line_id = syscall.line_id
            self.current_alarm.last_timestamp = syscall.timestamp_unix_in_ns()
        else:
            # check if correctness is same as current alarm
            if self.current_alarm.correct == correct:
                self.current_alarm.last_line_id = syscall.line_id
                self.current_alarm.last_timestamp = syscall.timestamp_unix_in_ns()
            else:
                # recursive call with same params after saving of current alarm when correctness changes
                self.end_alarm()
                self.add_or_update_alarm(syscall, correct)

    def end_alarm(self):
        """
            gets called after first not-alarm syscall from decision engine
            saves current alarm to alarm list
        """
        if self.current_alarm is not None:
            self.alarm_list.append(self.current_alarm)
            self.current_alarm = None

    def get_alarms_as_dict(self):
        """
            concludes all alarms to list in dictionary for easy json serialization
        """
        if self._alarm_dict is None:
            alarm_dict = {'alarms': []}
            for alarm in self.alarm_list:
                alarm_dict['alarms'].append(vars(alarm))
            return alarm_dict
        else:
            return self._alarm_dict
