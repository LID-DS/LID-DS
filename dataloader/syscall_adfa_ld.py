from dataloader.syscall import Syscall


class SyscallADFALD(Syscall):
    def __init__(self, syscall_id: str, mocked_time: int, recording_path: str, thread_id: int = 0):
        """
            represents one ADFA-LD Syscall as an object
            
            As the ADFA-LD Dataset does not contain syscall names but integers,
            the names are represented as integers in strings to fit the LID-DS 
            analysis approach.
            Does not feature lazy instantiation because no processing of the system call features is needed.
            Attributes can be retrieved by corresponding methods anyway to fit Syscall Interface.
            
            @param syscall_id: the syscalls integer value from the ADFA-LD dataset
            @param mocked_time: an integer representing a mocked timestamp
        """
        super().__init__()
        self.line_id = mocked_time
        self._name = syscall_id
        self._timestamp_unix = mocked_time
        self.recording_path = recording_path
        self._thread_id = thread_id

    def name(self) -> str:
        """
            @return: syscall name containing an integer
        """
        return self._name

    def timestamp_unix_in_ns(self) -> int:
        """
            @return: mocked timestamp
        """
        return self._timestamp_unix

    def thread_id(self) -> int:
        """
            @return: mocked thread id
        """
        return self._thread_id

    def __str__(self):
        # as dict
        return f"{{'name': {self._name}, 'timestamp': {self._timestamp_unix}, 'thread_id': {self._thread_id}}}"
