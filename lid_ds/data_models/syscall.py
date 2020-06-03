from terminaltables import AsciiTable

class SysCall():
    _repr_header = [
            'system call',
            'process_id',
            'thread_id',
            'cpu',
            'duration',
            'args_len',
            'res_len'
        ]

    def __init__(self, start_event, stop_event):
        self.start_event = start_event
        self.stop_event = stop_event

    @property
    def type(self):
        return self.start_event.event_type

    @property
    def process(self):
        return self.start_event.process

    @property
    def executing_cpu(self):
        return self.start_event.executing_cpu

    @property
    def thread_id(self):
        return self.start_event.thread_id

    @property
    def duration(self):
        return self.stop_event.event_time - self.start_event.event_time

    @property
    def start_timestamp(self):
        return self.start_event.event_time

    @property
    def end_timestamp(self):
        return self.stop_event.event_time

    @property
    def args(self):
        return self.start_event.init_args

    @property
    def res(self):
        return self.stop_event.init_args

    def _get_table_rep_row(self):
        return [
            self.type,
            self.process,
            str(self.thread_id),
            str(self.executing_cpu),
            str(self.duration.total_seconds()),
            str(len(self.args)),
            str(len(self.res))
        ]
    def __repr__(self):
        table_data = []
        table_data.append(SysCall._repr_header)
        table_data.append(self._get_table_rep_row())
        table = AsciiTable(table_data)
        table.title = 'SysCall ({})'.format(self.start_timestamp)
        return table.table

    @staticmethod
    def summary(syscalls):
        table_data = []
        table_data.append(SysCall._repr_header)
        for syscall in syscalls:
            table_data.append(syscall._get_table_rep_row())
        table = AsciiTable(table_data)
        table.title = 'System Calls ({})'.format(len(syscalls))
        return table.table




