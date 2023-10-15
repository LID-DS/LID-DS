import os
from typing import Generator
from dataloader.base_recording import BaseRecording
from dataloader.syscall_adfa_ld import SyscallADFALD as Syscall


class RecordingADFALDFixed(BaseRecording):
    def __init__(self, path: str, contains_attack: bool):
        """
        handles one ADFA-LD system call recording

        @param path: path to the recording
        @param contains_attack: is the recording containing an attack?
        """
        super().__init__()
        self.name = os.path.basename(path.rstrip('/'))
        self.path = path
        self._contains_attack = contains_attack
        self._metadata = self._collect_metadata()

    def syscalls(self) -> Generator[Syscall, None, None]:
        """
        generates ADFA-LD syscall objects with integers as names and mocked timestamps
        @return: System Call Object
        """
        if self._contains_attack:
            thread_id = 1
            for file in os.listdir(self.path):
                if file.endswith('.txt'):
                    file = os.path.join(self.path, file)
                    with open(file) as recording_file:
                        syscalls = recording_file.read().strip().split(' ')

                        # ADFA-LD has no syscall timestamps -> the get mocked with increasing integers
                        mocked_timestamp = 1
                        for syscall_id in syscalls:
                            syscall_object = Syscall(syscall_id, mocked_timestamp, self.path, thread_id)
                            mocked_timestamp += 1
                            yield syscall_object
                    thread_id += 1
        else:
            with open(self.path) as recording_file:
                syscalls = recording_file.read().strip().split(' ')

                # ADFA-LD has no syscall timestamps -> the get mocked with increasing integers
                mocked_timestamp = 1
                for syscall_id in syscalls:
                    syscall_object = Syscall(syscall_id, mocked_timestamp, self.path)
                    mocked_timestamp += 1
                    yield syscall_object

    def metadata(self):
        """
        @return: the metadata dictionary
        """
        return self._metadata

    def _collect_metadata(self) -> dict:
        """
        creates mocked metadata dictionary fitting the interface of the LID-DS Dataset metadata
        if recording contains an attack a mocked begin timestamp is added
        @return: metadata dictionary
        """
        if self._contains_attack:
            return {
                'exploit': True,
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
                'exploit': False,
                'time': {
                    'exploit': []
                }
            }
