from typing import Generator
from base_recording import BaseRecording
from syscall_adfa_ld import SyscallADFALD as Syscall


class RecordingADFALD(BaseRecording):
    def __init__(self, path, contains_attack):
        super().__init__()
        self.path = path
        self._contains_attack = contains_attack
        self._metadata = self._collect_metadata()

    def syscalls(self) -> Generator[Syscall, None, None]:
        with open(self.path) as recording_file:
            syscalls = recording_file.read().split(' ')

            mocked_timestamp = 1
            for syscall_id in syscalls:
                if len(syscall_id) > 0:
                    syscall_object = Syscall(syscall_id, mocked_timestamp)
                    mocked_timestamp += 1
                    yield syscall_object

    def metadata(self):
        return self._metadata

    def _collect_metadata(self) -> dict:
        if self._contains_attack:
            return {
                'time': {
                    'exploit': [
                        {
                            'absolute': 0
                        }
                    ]
                }
            }
        else:
            return {
                'time': {
                    'exploit': []
                }
            }
