from syscall import Syscall


class SyscallADFALD(Syscall):
    def __init__(self, syscall_id, mocked_time):
        super().__init__()
        self._name = syscall_id
        self._timestamp_unix = mocked_time

    def name(self) -> str:
        """
        gets syscall name from recorded line
        Returns:
            string: syscall name
        """
        return self._name

    def timestamp_unix_in_ns(self) -> int:
        return self._timestamp_unix

