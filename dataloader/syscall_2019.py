from time import mktime
from enum import IntEnum

from datetime import datetime

# Pre-compute epoch midnight once for fast timestamp arithmetic
_EPOCH_MIDNIGHT = mktime(datetime(1970, 1, 1).timetuple())

from dataloader.syscall import Syscall
from dataloader.direction import Direction


class SyscallSplitPart(IntEnum):
    TIMESTAMP = 1
    CPU = 2
    USER_ID = 3
    PROCESS_NAME = 4
    THREAD_ID = 5
    DIRECTION = 6
    SYSCALL_NAME = 7
    PARAMS_BEGIN = 8  # use [SyscallSplitPart.PARAMS_BEGIN:] to retrieve all args as list


class Param(IntEnum):
    NAME = 0
    VALUE = 1

class Syscall2019(Syscall):
    __slots__ = ('syscall_line', '_line_list', '_timestamp_datetime', '_timestamp_unix',
                 '_user_id', '_process_name', '_thread_id', '_direction', '_name', '_params',
                 '_res_value')

    def __init__(self, recording_path: str, syscall_line: str, line_id: int = -1):
        super().__init__()
        self.recording_path = recording_path
        self.syscall_line = syscall_line.rstrip()
        self._line_list = self.syscall_line.split(' ', SyscallSplitPart.PARAMS_BEGIN)
        self.line_id = line_id

        # Eager: only what the pipeline actually needs
        self._thread_id = int(self._line_list[SyscallSplitPart.THREAD_ID])
        dir_char = self._line_list[SyscallSplitPart.DIRECTION]
        self._direction = Direction.OPEN if dir_char == '>' else (Direction.CLOSE if dir_char == '<' else None)
        self._name = self._line_list[SyscallSplitPart.SYSCALL_NAME]

        # Eager: timestamp (always needed by analyze_syscall)
        s = self._line_list[SyscallSplitPart.TIMESTAMP]
        h, m, sec, us = int(s[0:2]), int(s[3:5]), int(s[6:8]), int(s[9:15])
        self._timestamp_unix = (_EPOCH_MIDNIGHT + h * 3600 + m * 60 + sec) * 1e9 + us

        # Eager: extract res= param (used by ReturnValue in hot path)
        self._res_value = None
        if len(self._line_list) > SyscallSplitPart.PARAMS_BEGIN:
            params_str = self._line_list[SyscallSplitPart.PARAMS_BEGIN]
            if params_str.startswith('res='):
                # Fast path: res is typically the first param
                space_idx = params_str.find(' ', 4)
                self._res_value = params_str[4:space_idx] if space_idx != -1 else params_str[4:]
            else:
                idx = params_str.find(' res=')
                if idx != -1:
                    start = idx + 5
                    space_idx = params_str.find(' ', start)
                    self._res_value = params_str[start:space_idx] if space_idx != -1 else params_str[start:]

        # Lazy: parse on access
        self._timestamp_datetime = None
        self._user_id = None
        self._process_name = None
        self._params = None

    def timestamp_unix_in_ns(self) -> float:
        return self._timestamp_unix

    def timestamp_datetime(self) -> datetime:
        if self._timestamp_datetime is None:
            s = self._line_list[SyscallSplitPart.TIMESTAMP]
            h, m, sec, us = int(s[0:2]), int(s[3:5]), int(s[6:8]), int(s[9:15])
            self._timestamp_datetime = datetime(1970, 1, 1, h, m, sec, us)
        return self._timestamp_datetime

    def user_id(self) -> int:
        if self._user_id is None:
            self._user_id = int(self._line_list[SyscallSplitPart.USER_ID])
        return self._user_id

    def process_id(self) -> int:
        return None

    def process_name(self) -> str:
        if self._process_name is None:
            self._process_name = self._line_list[SyscallSplitPart.PROCESS_NAME]
        return self._process_name

    def thread_id(self) -> int:
        return self._thread_id

    def name(self) -> str:
        return self._name

    def direction(self) -> Direction:
        return self._direction

    def params(self) -> dict:
        if self._params is None:
            self._params = {}
            if len(self._line_list) > SyscallSplitPart.PARAMS_BEGIN:
                for param_str in self._line_list[SyscallSplitPart.PARAMS_BEGIN].split(' '):
                    split = param_str.split('=', 1)
                    self._params[split[0]] = split[1] if len(split) == 2 else None
        return self._params

    def param(self, param_name: str):
        if param_name == 'res':
            return self._res_value
        return self.params().get(param_name, None)

