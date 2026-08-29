import base64
from datetime import datetime
from enum import IntEnum

from dataloader.direction import Direction
from dataloader.syscall import Syscall


class SyscallSplitPart(IntEnum):
    TIMESTAMP = 0
    USER_ID = 1
    PROCESS_ID = 2
    PROCESS_NAME = 3
    THREAD_ID = 4
    SYSCALL_NAME = 5
    DIRECTION = 6
    PARAMS_BEGIN = 7  # use [SyscallSplitPart.PARAMS_BEGIN:] to retrieve all args as list


class Param(IntEnum):
    NAME = 0
    VALUE = 1


class Syscall2021(Syscall):
    """
    represents one system call as an object created from a linestring out of an LID-DS 2021 recording
    """
    __slots__ = ('syscall_line', '_line_list', 'line_id', '_timestamp_unix', '_timestamp_datetime',
                 '_user_id', '_process_id', '_process_name', '_thread_id', '_name', '_direction',
                 '_params', 'recording_path')

    def __init__(self, recording_path: str, syscall_line: str, line_id: int = -1):
        self.recording_path = recording_path
        self.syscall_line = syscall_line
        self._line_list = syscall_line.split(' ', SyscallSplitPart.PARAMS_BEGIN)
        self.line_id = line_id
        # Eager: hot-path fields always accessed by pipeline
        self._thread_id = int(self._line_list[SyscallSplitPart.THREAD_ID])
        self._name = self._line_list[SyscallSplitPart.SYSCALL_NAME]
        dir_char = self._line_list[SyscallSplitPart.DIRECTION]
        self._direction = Direction.OPEN if dir_char == '>' else (Direction.CLOSE if dir_char == '<' else None)
        # Lazy: parse on access
        self._timestamp_unix = None
        self._timestamp_datetime = None
        self._user_id = None
        self._process_id = None
        self._process_name = None
        self._params = None

    def timestamp_unix_in_ns(self) -> int:
        if self._timestamp_unix is None:
            self._timestamp_unix = int(self._line_list[SyscallSplitPart.TIMESTAMP])
        return self._timestamp_unix

    def timestamp_datetime(self) -> datetime:
        if self._timestamp_datetime is None:
            self._timestamp_datetime = datetime.fromtimestamp(
                int(self._line_list[SyscallSplitPart.TIMESTAMP]) * 10 ** -9)
        return self._timestamp_datetime

    def user_id(self) -> int:
        if self._user_id is None:
            self._user_id = int(self._line_list[SyscallSplitPart.USER_ID])
        return self._user_id

    def process_id(self) -> int:
        if self._process_id is None:
            self._process_id = int(self._line_list[SyscallSplitPart.PROCESS_ID])
        return self._process_id

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
                    try:
                        self._params[split[Param.NAME]] = split[Param.VALUE]
                    except Exception:
                        pass
        return self._params

    def param(self, param_name: str, b64decode: bool = False):
        param_value = self.params().get(param_name)
        if param_value is None:
            return None
        if b64decode:
            return base64.b64decode(param_value)
        return param_value
