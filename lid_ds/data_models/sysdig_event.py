import re
from datetime import datetime
from terminaltables import AsciiTable

class SysdigEvent():
    _repr_header = [
            'system call',
            'process_id',
            'thread_id',
            'cpu',
            'event_time',
            'begin_event',
            'args'
        ]

    def __init__(self, sysdig_line):
        tokens = sysdig_line.decode("utf-8").split()

        self.sysdig_recording_index = int(tokens[0])
        self.event_time = float(tokens[1][:-3])
        self.executing_cpu = int(tokens[2])
        self.process = tokens[3]

        thread_id_regex = re.compile('([()])')
        self.thread_id = re.sub(thread_id_regex, '', tokens[4])

        self.enter_event = True if tokens[5] == '>' else False

        self.event_type = tokens[6]

        self.args = tokens[7:]
        #print('{} {} {} {} {} {} {}'.format(sysdig_recording_index, event_time, executing_cpu, process, thread_id, enter_event, event_type))

    def __repr__(self):
        table_data = []
        table_data.append(SysdigEvent._repr_header)
        repr_data = [
            self.event_type,
            self.process,
            str(self.thread_id),
            str(self.executing_cpu),
            str(self.event_time),
            str(self.enter_event),
            len(self.args)
        ]
        table_data.append(repr_data)
        table = AsciiTable(table_data)
        table.title = 'Sysdig Event #{}'.format(self.sysdig_recording_index)
        return table.table