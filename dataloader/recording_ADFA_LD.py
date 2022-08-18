from typing import Generator
from base_recording import BaseRecording
from syscall_adfa_ld import SyscallADFALD as Syscall

class RecordingADFALD(BaseRecording):
    def __init__(self, recording_path):
        super().__init__()
        self._recording_path = recording_path
        self.metadata = self._collect_metadata()

    def syscalls(self) -> Generator[Syscall, None, None]:
        with open(self._recording_path) as recording_file:
            syscalls = recording_file.read().split(' ')

            for syscall_id in syscalls:
                syscall_object = Syscall(syscall_id)
                yield syscall_object

    def metadata(self):
        return self._metadata()

    def _collect_metadata(self):
        pass
