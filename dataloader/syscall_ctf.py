from dataloader.syscall import Syscall


class SyscallCTF(Syscall):
    def __init__(self):
        super().__init__()
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