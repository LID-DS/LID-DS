import base64
from datetime import datetime
from enum import IntEnum
from typing import Union

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
    features lazy instantiation of syscall attributes

    all attributes need to be retrieved by corresponding methods

    """

    def __init__(self, recording_path: str, syscall_line: str, line_id: int = -1):
        self.syscall_line = syscall_line
        self._line_list = syscall_line.split(' ')
        self.line_id = line_id
        self._timestamp_unix = None
        self._timestamp_datetime = None
        self._user_id = None
        self._process_id = None
        self._process_name = None
        self._thread_id = None
        self._name = None
        self._direction = None
        self._params = None
        self.recording_path = recording_path

    def timestamp_unix_in_ns(self) -> int:
        """

        casts unix timestamp from string to int

        Returns:
            int: unix timestamp of syscall

        """
        if self._timestamp_unix is None:
            self._timestamp_unix = int(self._line_list[SyscallSplitPart.TIMESTAMP])

        return self._timestamp_unix

    def timestamp_datetime(self) -> datetime:
        """

        casts unix timestamp from string to python datetime object

        Returns:
            datetime: casted datetime object of syscall timestamp

        """
        if self._timestamp_datetime is None:
            self._timestamp_datetime = datetime.fromtimestamp(
                int(self._line_list[SyscallSplitPart.TIMESTAMP]) * 10 ** -9)

        return self._timestamp_datetime

    def user_id(self) -> int:
        """

        casts user_id from string to int

        Returns:
            int: user id
        """
        if self._user_id is None:
            self._user_id = int(self._line_list[SyscallSplitPart.USER_ID])

        return self._user_id

    def process_id(self) -> int:
        """

        casts process_id from string to int

        Returns:
            int: process id

        """
        if self._process_id is None:
            self._process_id = int(self._line_list[SyscallSplitPart.PROCESS_ID])

        return self._process_id

    def process_name(self) -> str:
        """

        extracts process name

        Returns:
            string: process Name

        """
        if self._process_name is None:
            self._process_name = self._line_list[SyscallSplitPart.PROCESS_NAME]

        return self._process_name

    def thread_id(self) -> int:
        """

        casts thread_id from string to int

        Returns:
            int: thread id

        """
        if self._thread_id is None:
            self._thread_id = int(self._line_list[SyscallSplitPart.THREAD_ID])

        return self._thread_id

    def name(self) -> str:
        """

        gets syscall name from recorded line

        Returns:
            string: syscall name

        """
        if self._name is None:
            self._name = self._line_list[SyscallSplitPart.SYSCALL_NAME]

        return self._name

    def direction(self) -> Direction:
        """

        sets direction based on chars '<' and '>', casts to OPEN/CLOSE in enum

        Returns:
            Direction: the direction of the syscall

        """
        if self._direction is None:
            dir_char = self._line_list[SyscallSplitPart.DIRECTION]
            if dir_char == '>':
                self._direction = Direction.OPEN
            elif dir_char == '<':
                self._direction = Direction.CLOSE

        return self._direction

    def params(self) -> dict:
        """

        extracts params from param list and saves its names and values as dict

        Returns:
            dict: the syscalls parameters

        """
        if self._params is None:
            self._params = {}
            if len(self._line_list) > 7:  # check if params are given
                for param in self._line_list[SyscallSplitPart.PARAMS_BEGIN:]:
                    split = param.split('=', 1)
                    try:
                        self._params[split[Param.NAME]] = split[Param.VALUE]
                    except:
                        pass
        return self._params

    def param(self, param_name: str, b64decode: bool = False) -> Union[bytes, str]:
        """

        runs the params() method and returns the requested
        decodes base64 strings if activated

        Returns:
            str or bytes: syscall parameter value

        """
        params = self.params()
        try:
            param_value = params[param_name]
            if b64decode:
                return base64.b64decode(param_value)
            else:
                return param_value
        except KeyError:
            pass
