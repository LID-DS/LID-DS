from datetime import datetime
from typing import Union

from dataloader.direction import Direction


class Syscall:
    """
    represents one system call
    """

    def __init__(self):
        self.recording_path = None
        self.line_id = None

    def timestamp_unix_in_ns(self) -> int:
        """
        Returns:
            int: unix timestamp of syscall
        """
        raise NotImplemented

    def timestamp_datetime(self) -> datetime:
        """
        Returns:
            datetime: casted datetime object of syscall timestamp
        """
        raise NotImplemented

    def user_id(self) -> int:
        """
        Returns:
            int: user id
        """
        raise NotImplemented

    def process_id(self) -> int:
        """
        Returns:
            int: process id
        """
        raise NotImplemented

    def process_name(self) -> str:
        """
        Returns:
            string: process Name
        """
        raise NotImplemented

    def thread_id(self) -> int:
        """
        casts thread_id from string to int

        Returns:
            int: thread id
        """
        raise NotImplemented

    def name(self) -> str:
        """
        Returns:
            string: syscall name
        """
        raise NotImplemented

    def direction(self) -> Direction:
        """
        Returns:
            Direction: the direction of the syscall
        """
        raise NotImplemented

    def params(self) -> dict:
        """
        Returns:
            dict: the syscalls parameters
        """
        raise NotImplemented

    def param(self, param_name: str, b64decode: bool = False) -> Union[bytes, str]:
        """
        Returns:
            str or bytes: syscall parameter value
        """
        raise NotImplemented
