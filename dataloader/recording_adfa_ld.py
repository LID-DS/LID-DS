from typing import Generator
from dataloader.base_recording import BaseRecording
from dataloader.syscall_adfa_ld import SyscallADFALD as Syscall


class RecordingADFALD(BaseRecording):
    def __init__(self, path: str, contains_attack: bool, cache_lines: bool = False):
        """
        handles one ADFA-LD system call recording

        @param path: path to the recording
        @param contains_attack: is the recording containing an attack?
        @param cache_lines: if True, cache raw file content in memory
        """
        super().__init__()
        self.path = path
        self._contains_attack = contains_attack
        self._cache_lines = cache_lines
        self._cached_content = None
        self._metadata = self._collect_metadata()

    def syscalls(self) -> Generator[Syscall, None, None]:
        """
        generates ADFA-LD syscall objects with integers as names and mocked timestamps
        @return: System Call Object
        """
        if self._cache_lines:
            if self._cached_content is None:
                with open(self.path) as recording_file:
                    self._cached_content = recording_file.read().strip()
            content = self._cached_content
        else:
            with open(self.path) as recording_file:
                content = recording_file.read().strip()

        for mocked_timestamp, syscall_id in enumerate(content.split(' '), start=1):
            yield Syscall(syscall_id, mocked_timestamp, self.path)

    def clear_cache(self):
        """Frees the content cache."""
        self._cached_content = None

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
