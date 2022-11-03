from dataloader.syscall import Syscall
from dataloader.direction import Direction


class SyscallCTF(Syscall):
    def __init__(self, name: str, thread_id: int, process_id: int, process_name: str, direction: Direction, timestamp: int, recording_path: str, line_id: int):
        super().__init__()
        self.line_id = line_id
        self._timestamp_unix = timestamp
        self._process_id = process_id
        self._process_name = process_name
        self._thread_id = thread_id
        self._name = name
        self._direction = direction
        self.recording_path = recording_path

    def name(self) -> str:
        """
            @return: syscall name containing an integer
        """
        return self._name

    def timestamp_unix_in_ns(self) -> int:
        """
            @return: unix timestamp of syscall
        """
        return self._timestamp_unix

    def thread_id(self) -> int:
        """
            @return: syscall thread id
        """
        return self.thread_id

    def process_id(self) -> int:
        """
            @return: syscall name containing an integer
        """
        return self._process_id

    def direction(self) -> Direction:
        """
            @return: syscall direction
        """
        return self._direction

    def process_name(self) -> str:
        """
            @return: syscall process name
        """
        return self._process_name

